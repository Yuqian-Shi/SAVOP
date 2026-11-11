"use strict";
const $ = id => document.getElementById(id);
const NS = "http://www.w3.org/2000/svg";
let summary, graphData, detailASN=4134, offset=0, neighborTotal=0, viewEpoch=0, detailEpoch=0;
let svgGroup, transform={x:0,y:0,k:1};
const esc = text => String(text).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmt = n => Number(n).toLocaleString('en-US');
async function api(path, params={}){const r=await fetch(path+'?'+new URLSearchParams(params));const d=await r.json();if(!r.ok)throw Error(d.error||r.statusText);return d;}
function layer(){return $('layer').value;}
function relation(e,asn){if(e.relation==='p2c')return e.provider===asn?'下游客户':'上游提供商';return ({p2p:'对等',unknown:'未知',conflict:'推断冲突'})[e.relation];}
function updateMetrics(){const s=summary.layers[layer()],c=s.relations_and_evidence;$('metrics').innerHTML=[['AS数量',s.nodes,'全层去重节点'],['连接数量',s.edges,'全层去重AS对'],['有RIS观测的连接',(c.inferred_and_observed||0)+(c.observed_only||0),'不是全网覆盖率'],['连通分量',s.connected_components,'仅邻接图，不代表报文可达']].map(([t,n,f])=>`<div class="metric">${t}<strong>${fmt(n)}</strong><span>${f}</span></div>`).join('');$('exportAll').href='/api/export?layer='+layer();}
function node(tag,attrs={}){const el=document.createElementNS(NS,tag);for(const[k,v]of Object.entries(attrs))el.setAttribute(k,v);return el;}
function applyTransform(){if(svgGroup)svgGroup.setAttribute('transform',`translate(${transform.x},${transform.y}) scale(${transform.k})`);}
function draw(data){const svg=$('graph');svg.replaceChildren();transform={x:0,y:0,k:1};svgGroup=node('g');svg.append(svgGroup);const adjacency=new Map(data.nodes.map(n=>[n.asn,[]]));for(const e of data.edges){adjacency.get(e.u).push([e.v,e]);adjacency.get(e.v).push([e.u,e]);}const depth=new Map([[data.center,0]]),tree=[],queue=[data.center];for(let i=0;i<queue.length;i++){const u=queue[i];for(const[v,e]of adjacency.get(u).sort((a,b)=>a[0]-b[0]))if(!depth.has(v)){depth.set(v,depth.get(u)+1);queue.push(v);tree.push(e);}}const sizes=new Map(),indexes=new Map();for(const n of data.nodes){const d=depth.get(n.asn)||0;sizes.set(d,(sizes.get(d)||0)+1);}const hasOuter=sizes.has(2);const list=data.nodes.map(n=>{const d=depth.get(n.asn)||0,i=indexes.get(d)||0;indexes.set(d,i+1);const angle=i*2*Math.PI/Math.max(1,sizes.get(d));const rx=hasOuter&&d===1?260:410,ry=hasOuter&&d===1?140:235;return {...n,x:d===0?500:500+rx*Math.cos(angle),y:d===0?300:300+ry*Math.sin(angle)};});const byId=new Map(list.map(n=>[n.asn,n]));
// Stable ellipse: positions have no geographic/latency meaning. Hide lateral
// edges by default to avoid a dense hairball; exports retain every induced edge.
const drawn=$('drawEdges').value==='all'?data.edges:tree;
$('viewTitle').textContent=`AS${data.center} · ${data.nodes.length}节点 / 绘制${drawn.length}条（邻域共${data.edges.length}条）`;
const edgeEls=drawn.map(e=>{const line=node('line',{class:'graph-edge '+e.relation});const title=node('title');title.textContent=`AS${e.u} — AS${e.v} / ${e.relation}`;line.append(title);line.addEventListener('click',()=>showEdge(e.u,e.v).catch(error));svgGroup.append(line);return[e,line];});
const labelBoxes=[{x:522,y:290,w:75,h:16}];
function labelX(n,radius){
  if(n.asn===data.center)return radius+5;
  const w=('AS'+n.asn).length*7.5,x=n.x<500?-radius-5-w:radius+5;
  const b={x:n.x+x,y:n.y-10,w,h:16};
  if(b.x<5||b.x+w>995||b.y<5||b.y+16>595)return null;
  if(labelBoxes.some(a=>a.x<b.x+b.w&&a.x+a.w>b.x&&a.y<b.y+b.h&&a.y+a.h>b.y))return null;
  if(list.some(a=>a.asn!==n.asn&&Math.hypot(a.x-Math.max(b.x,Math.min(b.x+w,a.x)),a.y-Math.max(b.y,Math.min(b.y+16,a.y)))<14))return null;
  labelBoxes.push(b);return x;
}
const nodes=list.map(n=>{
  const g=node('g',{class:'graph-node'+(n.asn===data.center?' center':''),tabindex:0,'aria-label':`AS${n.asn}，${n.degree}个邻居`});
  const radius=n.asn===data.center?17:Math.min(10,4+Math.log2(n.degree+1)*.7);
  const circle=node('circle',{r:radius}),title=node('title');title.textContent=`AS${n.asn} · ${n.degree}邻居`;g.append(circle,title);
  const lx=labelX(n,radius);if(lx!==null){const t=node('text',{x:lx,y:4});t.textContent='AS'+n.asn;g.append(t);}
  g.addEventListener('click',()=>showAS(n.asn).catch(error));
  g.addEventListener('dblclick',()=>{$('asn').value=n.asn;loadGraph();});
  g.addEventListener('keydown',e=>{if(e.key==='Enter')showAS(n.asn).catch(error);});
  g.addEventListener('pointerdown',e=>{e.stopPropagation();g.setPointerCapture(e.pointerId);const move=ev=>{const p=svg.createSVGPoint();p.x=ev.clientX;p.y=ev.clientY;const at=p.matrixTransform(svgGroup.getScreenCTM().inverse());n.x=at.x;n.y=at.y;update();};g.addEventListener('pointermove',move);g.addEventListener('pointerup',()=>g.removeEventListener('pointermove',move),{once:true});});
  svgGroup.append(g);return[n,g,radius];
});
function update(){for(const[e,line]of edgeEls){const a=byId.get(e.u),b=byId.get(e.v),dx=b.x-a.x,dy=b.y-a.y,len=Math.max(1,Math.hypot(dx,dy));const gap=n=>n.asn===data.center?23:Math.min(10,4+Math.log2(n.degree+1)*.7)+6;line.setAttribute('x1',a.x+dx/len*gap(a));line.setAttribute('y1',a.y+dy/len*gap(a));line.setAttribute('x2',b.x-dx/len*gap(b));line.setAttribute('y2',b.y-dy/len*gap(b));}for(const[n,g]of nodes)g.setAttribute('transform',`translate(${n.x},${n.y})`);}update();applyTransform();}
function error(e){$('status').textContent='操作未完成：'+e.message;}
async function loadGraph(){const epoch=++viewEpoch;++detailEpoch;graphData=null;$('neighborRows').replaceChildren();$('detail').textContent='正在查询…';$('detailTitle').textContent='AS信息';$('neighborCount').textContent='';$('prev').disabled=true;$('next').disabled=true;updateMetrics();try{const text=$('asn').value.trim().replace(/^AS/i,'');if(!/^\d+$/.test(text))throw Error('请输入整数ASN，例如4134');$('status').textContent='正在查询…';const data=await api('/api/graph',{layer:layer(),asn:text,hops:$('hops').value,limit:$('limit').value,evidence:$('evidence').value});if(epoch!==viewEpoch)return;graphData=data;draw(data);$('boundary').textContent=`该筛选下中心AS有${fmt(data.first_hop_total)}个一跳邻居。当前视图${data.truncated?'已按上限截断':'未触及节点上限'}，另有${fmt(data.boundary_edges_not_drawn)}条连接通往视图外。显示选择按ASN排序，不作为实验抽样。`;$('status').textContent='已载入。图形只显示局部，搜索和全量CSV覆盖整个数据层。';$('edgeDetail').textContent='点击图中连线或邻居表中的“证据”。';await showAS(data.center);}catch(e){if(epoch===viewEpoch){graphData=null;$('graph').replaceChildren();$('viewTitle').textContent='';$('detail').textContent='未取得数据';$('boundary').textContent='没有生成新视图；请核对ASN与数据层。';error(e);}}}
async function showAS(asn,page=0){const epoch=++detailEpoch;const d=await api('/api/as',{layer:layer(),asn,offset:page});if(epoch!==detailEpoch)return;detailASN=asn;offset=page;neighborTotal=d.neighbor_total;$('detailTitle').textContent='AS'+asn;$('detail').innerHTML=`<dl><dt>全层邻居</dt><dd>${fmt(d.node.degree)}</dd><dt>推断的上游 / 下游 / 对等</dt><dd>${d.node.providers} / ${d.node.customers} / ${d.node.peers}</dd><dt>未知或冲突关系</dt><dd>${d.node.unknown}</dd><dt>RIS观测的起源前缀</dt><dd>${fmt(d.unique_observed_prefixes)}（非授权证明）</dd></dl><details><summary>前缀样例（最多100条来源记录）</summary><ul>${d.prefix_sample.map(p=>`<li>${esc(p.prefix)}<br><span class="source-chip">${esc(p.source)}</span></li>`).join('')||'<li>本层没有可用前缀观测，不代表没有前缀。</li>'}</ul></details>`;$('neighborCount').textContent=`AS${asn} · ${offset+1}—${Math.min(offset+100,neighborTotal)} / ${neighborTotal}`;$('prev').disabled=offset===0;$('next').disabled=offset+100>=neighborTotal;$('neighborRows').innerHTML=d.neighbors.map(e=>{const other=e.u===asn?e.v:e.u;return `<tr><td><button data-asn="${other}">AS${other}</button></td><td>${relation(e,asn)}</td><td>${e.inferred_sources.map(esc).join('<br>')||'—'}</td><td>${e.observed_sources.map(esc).join('<br>')||'本次未观测'}</td><td><button data-u="${e.u}" data-v="${e.v}">证据</button></td></tr>`;}).join('');}
async function showEdge(u,v){const d=await api('/api/edge',{layer:layer(),u,v});$('edgeDetail').replaceChildren();const label=document.createElement('strong');label.textContent=`AS${u} — AS${v}`;$('edgeDetail').append(label);const pre=document.createElement('pre');pre.textContent=JSON.stringify(d,null,2);$('edgeDetail').append(pre);}
$('neighborRows').addEventListener('click',e=>{const b=e.target.closest('button');if(!b)return;if(b.dataset.asn){$('asn').value=b.dataset.asn;loadGraph();}else showEdge(b.dataset.u,b.dataset.v).catch(error);});
$('search').addEventListener('submit',e=>{e.preventDefault();loadGraph();});for(const id of ['layer','hops','limit','evidence'])$(id).addEventListener('change',loadGraph);
$('prev').onclick=()=>showAS(detailASN,Math.max(0,offset-100)).catch(error);$('next').onclick=()=>showAS(detailASN,offset+100).catch(error);
$('reset').onclick=()=>{transform={x:0,y:0,k:1};applyTransform();};
$('drawEdges').onchange=()=>{if(graphData)draw(graphData);};
$('graph').addEventListener('wheel',e=>{e.preventDefault();transform.k=Math.max(.3,Math.min(4,transform.k*(e.deltaY<0?1.1:.9)));applyTransform();},{passive:false});
$('graph').addEventListener('pointerdown',e=>{if(e.target!==$('graph'))return;const svg=$('graph');svg.setPointerCapture(e.pointerId);let x=e.clientX,y=e.clientY;const move=ev=>{const scale=1000/svg.clientWidth;transform.x+=(ev.clientX-x)*scale;transform.y+=(ev.clientY-y)*scale;x=ev.clientX;y=ev.clientY;applyTransform();};svg.addEventListener('pointermove',move);svg.addEventListener('pointerup',()=>svg.removeEventListener('pointermove',move),{once:true});});
$('exportView').onclick=async()=>{if(!graphData)return;const captured=graphData;try{const sources=await api('/api/sources');const blob=new Blob([JSON.stringify({...captured,sources},null,2)],{type:'application/json'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=`AS${captured.center}-${captured.layer}-display.json`;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),5000);}catch(e){error(e);}};
api('/api/summary').then(d=>{summary=d;updateMetrics();loadGraph();}).catch(error);
