//! Bounded systematic datagram redundancy. Original packets deliver immediately;
//! repair never bypasses the authenticated outer admission or inner Noise checks.
use anyhow::{Result,ensure};
use std::{collections::{BTreeMap,HashMap,VecDeque},time::Duration};
use tokio::time::Instant;

const HEADER:usize=16;
const MAX_PACKET:usize=2048;
const MAGIC:&[u8;4]=b"EZR2";
fn multiply(mut a:u8,mut b:u8)->u8{let mut result=0;while b!=0{if b&1!=0{result^=a;}let high=a&128;a<<=1;if high!=0{a^=0x1d;}b>>=1;}result}
fn power(a:u8,n:usize)->u8{let mut out=1;for _ in 0..n{out=multiply(out,a);}out}
fn inverse(a:u8)->u8{power(a,254)}
fn coefficient(parity:usize,data:usize)->u8{
    // Cauchy matrix: disjoint x/y coordinates yield any invertible square
    // submatrix, unlike appending an arbitrary Vandermonde row to identity.
    inverse((parity as u8)^(16+data as u8))
}

pub struct Encoder{data:u8,parity:u8,next:u64,shards:Vec<Vec<u8>>}
impl Encoder{
    pub fn new(data:u8,parity:u8)->Result<Self>{ensure!((1..=16).contains(&data)&&(1..=4).contains(&parity),"Mirage redundancy needs 1..16 data and 1..4 parity shards");let mut seed=[0;8];rustls::crypto::ring::default_provider().secure_random.fill(&mut seed).map_err(|_|anyhow::anyhow!("Mirage repair randomness unavailable"))?;Ok(Self{data,parity,next:u64::from_be_bytes(seed)&0x7fff_ffff_ffff_ffff,shards:Vec::new()})}
    fn packet(&self,index:u8,body:&[u8])->Vec<u8>{let mut bytes=Vec::with_capacity(HEADER+body.len());bytes.extend_from_slice(MAGIC);bytes.extend_from_slice(&self.next.to_be_bytes());bytes.extend_from_slice(&[self.data,self.parity,index,0]);bytes.extend_from_slice(body);bytes}
    pub fn encode(&mut self,bytes:&[u8])->Result<Vec<Vec<u8>>>{
        ensure!(bytes.len()<=MAX_PACKET-2,"Mirage redundancy packet too large");ensure!(self.next<u64::MAX,"Mirage redundancy group exhausted");
        let mut shard=Vec::with_capacity(bytes.len()+2);shard.extend_from_slice(&(bytes.len()as u16).to_be_bytes());shard.extend_from_slice(bytes);
        let mut result=vec![self.packet(self.shards.len()as u8,&shard)];self.shards.push(shard);
        if self.shards.len()==usize::from(self.data){
            let length=self.shards.iter().map(Vec::len).max().unwrap();
            for parity in 0..self.parity{
                let mut repair=vec![0;length];
                for(index,shard)in self.shards.iter().enumerate(){let factor=coefficient(parity as usize,index);for(out,byte)in repair.iter_mut().zip(shard){*out^=multiply(factor,*byte);}}
                result.push(self.packet(self.data+parity,&repair));
            }
            self.shards.clear();self.next+=1;
        }
        Ok(result)
    }
}
struct Group{created:Instant,shards:Vec<Option<Vec<u8>>>,delivered:Vec<bool>}
struct Retired{last:u64,touched:Instant}
pub struct Decoder{data:u8,parity:u8,groups:HashMap<u64,Group>,order:VecDeque<u64>,retired:BTreeMap<u64,Retired>}
impl Decoder{
    pub fn new(data:u8,parity:u8)->Result<Self>{Encoder::new(data,parity)?;Ok(Self{data,parity,groups:HashMap::new(),order:VecDeque::new(),retired:BTreeMap::new()})}
    fn retire(&mut self,id:u64){
        let mut first=id;let mut last=id;
        if let Some((&start,range))=self.retired.range(..=id).next_back(){
            if range.last>=id{return;}
            if range.last.checked_add(1)==Some(id){first=start;self.retired.remove(&start);}
        }
        if let Some((&start,range))=self.retired.range(id..).next(){
            if id.checked_add(1)==Some(start){last=range.last;self.retired.remove(&start);}
        }
        // Normal monotonically increasing groups merge into one range. Even
        // arbitrary authenticated sparse IDs cannot make fresh data unavailable.
        if self.retired.len()>=8192 {
            if let Some(old)=self.retired.iter().min_by_key(|(_,range)|range.touched).map(|(id,_)|*id){self.retired.remove(&old);}
        }
        self.retired.insert(first,Retired{last,touched:Instant::now()});
    }
    pub fn decode(&mut self,packet:&[u8])->Result<Vec<Vec<u8>>>{
        ensure!(packet.len()>=HEADER+2&&packet.len()<=HEADER+MAX_PACKET&&&packet[..4]==MAGIC,"invalid Mirage repair envelope");
        ensure!(packet[12]==self.data&&packet[13]==self.parity&&packet[15]==0,"authenticated Mirage redundancy contract mismatch");
        let index=usize::from(packet[14]);ensure!(index<usize::from(self.data+self.parity),"invalid Mirage shard index");
        let id=u64::from_be_bytes(packet[4..12].try_into().unwrap());
        self.retired.retain(|_,range|range.touched.elapsed()<Duration::from_secs(32));
        if self.retired.range(..=id).next_back().is_some_and(|(_,range)|range.last>=id){return Ok(vec![]);}
        let expired=self.groups.iter().filter(|(_,group)|group.created.elapsed()>=Duration::from_secs(2)).map(|(id,_)|*id).collect::<Vec<_>>();
        for old in expired{self.groups.remove(&old);self.retire(old);}
        self.order.retain(|id|self.groups.contains_key(id));
        if !self.groups.contains_key(&id){if self.groups.len()>=32{if let Some(old)=self.order.pop_front(){self.groups.remove(&old);self.retire(old);}}self.order.push_back(id);self.groups.insert(id,Group{created:Instant::now(),shards:vec![None;usize::from(self.data+self.parity)],delivered:vec![false;usize::from(self.data)]});}
        let group=self.groups.get_mut(&id).unwrap();if group.shards[index].is_some(){return Ok(vec![]);}
        group.shards[index]=Some(packet[HEADER..].to_vec());let mut output=Vec::new();
        if index<usize::from(self.data){output.push(extract(group.shards[index].as_ref().unwrap())?);group.delivered[index]=true;}
        if group.delivered.iter().all(|v|*v){self.groups.remove(&id);self.order.retain(|old|*old!=id);self.retire(id);return Ok(output);}
        let selected=group.shards.iter().enumerate().filter_map(|(index,shard)|shard.as_ref().map(|bytes|(index,bytes.clone()))).take(usize::from(self.data)).collect::<Vec<_>>();
        if selected.len()<usize::from(self.data){return Ok(output);}
        let n=usize::from(self.data);let width=selected.iter().map(|(_,bytes)|bytes.len()).max().unwrap();
        let mut matrix=vec![vec![0u8;n];n];let mut payloads=vec![vec![0;width];n];
        for(row,(index,bytes))in selected.iter().enumerate(){if *index<n{matrix[row][*index]=1;}else{for column in 0..n{matrix[row][column]=coefficient(*index-n,column);}}payloads[row][..bytes.len()].copy_from_slice(bytes);}
        for column in 0..n{
            let pivot=(column..n).find(|row|matrix[*row][column]!=0).ok_or_else(||anyhow::anyhow!("singular Mirage repair matrix"))?;
            matrix.swap(pivot,column);payloads.swap(pivot,column);let factor=inverse(matrix[column][column]);
            for value in &mut matrix[column]{*value=multiply(*value,factor);}for value in &mut payloads[column]{*value=multiply(*value,factor);}
            for row in 0..n{if row==column{continue;}let factor=matrix[row][column];if factor==0{continue;}
                for index in 0..n{matrix[row][index]^=multiply(factor,matrix[column][index]);}
                for index in 0..width{payloads[row][index]^=multiply(factor,payloads[column][index]);}
            }
        }
        for(index,bytes)in payloads.into_iter().enumerate(){if !group.delivered[index]{output.push(extract(&bytes)?);group.delivered[index]=true;}}
        self.groups.remove(&id);self.order.retain(|old|*old!=id);self.retire(id);
        Ok(output)
    }
}
fn extract(bytes:&[u8])->Result<Vec<u8>>{ensure!(bytes.len()>=2,"short repair payload");let size=usize::from(u16::from_be_bytes(bytes[..2].try_into().unwrap()));ensure!(size<=MAX_PACKET-2&&size+2<=bytes.len(),"invalid repaired length");Ok(bytes[2..size+2].to_vec())}
pub const OVERHEAD:usize=HEADER+2;

#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn any_four_losses_recover_without_delaying_original_packets()->Result<()> {
        let mut encoder=Encoder::new(6,4)?;let input=(0..6).map(|index|vec![index;index as usize*17+1]).collect::<Vec<_>>();let mut packets=Vec::new();
        for data in &input{packets.extend(encoder.encode(data)?);}
        assert_eq!(packets.len(),10);
        for mask in 0u16..1024{if mask.count_ones()!=4{continue;}let mut decoder=Decoder::new(6,4)?;let mut got=Vec::new();
            for(index,packet)in packets.iter().enumerate(){if mask&(1<<index)==0{got.extend(decoder.decode(packet)?);assert!(decoder.decode(packet)?.is_empty());}}
            got.sort();let mut expected=input.clone();expected.sort();assert_eq!(got,expected,"mask{mask}");
        }Ok(())
    }
    #[test]
    fn partial_group_delivers_immediately_and_memory_is_bounded()->Result<()> {
        let mut encoder=Encoder::new(4,2)?;let packet=encoder.encode(b"small")?.remove(0);let mut decoder=Decoder::new(4,2)?;
        assert_eq!(decoder.decode(&packet)?,vec![b"small".to_vec()]);
        for group in 1..100u64{let mut next=packet.clone();next[4..12].copy_from_slice(&group.to_be_bytes());decoder.decode(&next)?;assert!(decoder.groups.len()<=32);}
        assert!(decoder.decode(&[0;20]).is_err());Ok(())
    }
    #[test]
    fn sustained_distinct_groups_never_refuse_fresh_originals_after_replay_bookkeeping_fills()->Result<()> {
        let mut encoder=Encoder::new(1,1)?;let mut decoder=Decoder::new(1,1)?;
        for index in 0..20_000u64{
            let payload=index.to_be_bytes();let packets=encoder.encode(&payload)?;
            assert_eq!(decoder.decode(&packets[0])?,vec![payload.to_vec()],"group{index}");
            assert!(decoder.decode(&packets[1])?.is_empty());
            assert!(decoder.groups.len()<=32&&decoder.retired.len()<=8192);
        }Ok(())
    }
}
