import fs from 'node:fs';
import path from 'node:path';
import ts from 'typescript';
const root=path.resolve(import.meta.dirname,'..');
const source=fs.readFileSync(path.join(root,'src/main.tsx'),'utf8');
const locale=fs.readFileSync(path.join(root,'src/localization.ts'),'utf8');
const sf=ts.createSourceFile('main.tsx',source,ts.ScriptTarget.Latest,true,ts.ScriptKind.TSX);
const basePath=path.join(root,'tools/i18n-baseline.json');
const collect=new Set();
const cleaned=s=>s.replace(/\s+/g,' ').trim();
function walk(node){
 if(ts.isJsxText(node)) {const s=cleaned(node.text);if(/[a-záàâãçéêíóôõú]/i.test(s)&&s.length>2)collect.add(s);}
 if(ts.isJsxAttribute(node)&&node.initializer&&ts.isStringLiteral(node.initializer)) {const s=cleaned(node.initializer.text); if(['placeholder','title','aria-label'].includes(node.name.text)&&/[a-záàâãçéêíóôõú]/i.test(s))collect.add(s);}
 ts.forEachChild(node,walk);
}
walk(sf);
const labels=[...collect].sort();
if(process.argv.includes('--update-baseline')){
 fs.writeFileSync(basePath,JSON.stringify(labels,null,2)+'\n');console.log('i18n baseline updated:',labels.length);process.exit(0);
}
const baseline=JSON.parse(fs.readFileSync(basePath,'utf8'));
const allowed=new Set(baseline);
const missing=labels.filter(label=>!allowed.has(label));
const entries=[...locale.matchAll(/^\s*'((?:\\'|[^'])+)':'((?:\\'|[^'])+)'\s*,?\s*$/gm)];
const dictionary=new Map();const failures=[];
for(const [,pt,en] of entries){if(dictionary.has(pt))failures.push('Duplicate key: '+pt);dictionary.set(pt,en);if(!en.trim()||pt===en&&/[áàâãçéêíóôõú]/i.test(pt))failures.push('Invalid translation: '+pt);}
for(const label of missing){if(!dictionary.has(label))failures.push('New UI text needs English translation in localization.ts: '+label);}
// The system translation table must have identical keys in both languages.
const objects=[...source.matchAll(/\b(pt|en):\{(system:.*?warning:'.*?')\}/gs)];
const maps=new Map(objects.map(([,lang,body])=>[lang,[...body.matchAll(/(?:^|,)\s*([a-zA-Z]+):/g)].map(x=>x[1])]));
if(maps.size!==2||JSON.stringify(maps.get('pt'))!==JSON.stringify(maps.get('en'))) failures.push('PT/EN message keys differ');
if(failures.length){console.error(failures.join('\n'));process.exit(1);}
console.log('i18n check OK:',labels.length,'UI labels,',dictionary.size,'legacy translations, PT/EN parity');
