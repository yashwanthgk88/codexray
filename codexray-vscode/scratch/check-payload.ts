import * as fs from "fs";
import * as path from "path";
import { getParsers } from "../src/analyzer/parser";
import { buildModel } from "../src/analyzer/analyze";
import { buildPayload } from "../src/analyzer/payload";
import { adapterForExt } from "../src/analyzer/adapters";
const IGNORE = new Set([".git","__pycache__","node_modules",".venv","venv","env"]);
function collect(root:string){const out:any[]=[];const st=[root];while(st.length){const d=st.pop()!;let es;try{es=fs.readdirSync(d,{withFileTypes:true});}catch{continue;}for(const e of es){const full=path.join(d,e.name);if(e.isDirectory()){if(!IGNORE.has(e.name))st.push(full);}else if(e.isFile()){const a=adapterForExt(path.extname(e.name));if(!a)continue;try{out.push({rel:path.relative(root,full),src:fs.readFileSync(full,"utf-8"),lang:a.id});}catch{}}}}return out;}
(async()=>{
  const root="/Users/yashwanthgk/Downloads/DVWA-master";
  const files=collect(root);
  const parsers=await getParsers(path.join(__dirname,"..","dist"),files.map((f:any)=>f.lang));
  const p=buildPayload(buildModel(root,files,parsers));
  console.log("stats:",JSON.stringify(p.stats));
  console.log("total flows:",p.flows.length,"| tainted:",p.flows.filter((f:any)=>f.tainted).length);
  const byCat:any={};for(const f of p.flows)byCat[f.category]=(byCat[f.category]||0)+1;
  console.log("by category:",JSON.stringify(byCat));
  const t=p.flows.find((f:any)=>f.tainted&&f.category==="command_exec");
  console.log("\nsample tainted command_exec flow:");
  console.log(JSON.stringify({sink:t.sink,sinkFile:t.sinkFile,sinkLine:t.sinkLine,origin:t.origin,originLine:t.originLine,via:t.via,originCode:t.originCode,sinkCode:t.sinkCode,sinkKey_hasBody:!!p.funcs[t.sinkKey]},null,2));
})();
