import * as fs from "fs"; import * as path from "path";
import { getParsers } from "../src/analyzer/parser";
import { buildModel } from "../src/analyzer/analyze";
import { buildPayload } from "../src/analyzer/payload";
import { adapterForExt } from "../src/analyzer/adapters";
const IG=new Set([".git","__pycache__","node_modules"]);
function col(r:string){const o:any[]=[];const s=[r];while(s.length){const d=s.pop()!;let es;try{es=fs.readdirSync(d,{withFileTypes:true})}catch{continue}for(const e of es){const f=path.join(d,e.name);if(e.isDirectory()){if(!IG.has(e.name))s.push(f)}else{const a=adapterForExt(path.extname(e.name));if(a)try{o.push({rel:path.relative(r,f),src:fs.readFileSync(f,"utf8"),lang:a.id})}catch{}}}}return o}
(async()=>{const r="/Users/yashwanthgk/Downloads/DVWA-master";const files=col(r);const p=await getParsers(path.join(__dirname,"..","dist"),files.map((f:any)=>f.lang));const pl=buildPayload(buildModel(r,files,p));fs.writeFileSync("scratch/dvwa-payload.json",JSON.stringify(pl));console.log("wrote payload, flows=",pl.flows.length)})();
