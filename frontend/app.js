// AI Bug Hunter dashboard logic
let API_BASE = localStorage.getItem("bugHunterApiUrl") || "";
const $ = id => document.getElementById(id);
let latestReport = null;
$("apiUrl").value = API_BASE;
$("saveApi").addEventListener("click",()=>{let value=$("apiUrl").value.trim();while(value.endsWith("/"))value=value.slice(0,-1);if(value && !(value.startsWith("https://") || value.startsWith("http://")))return message("Backend URL must start with https:// or http://","error");API_BASE=value;localStorage.setItem("bugHunterApiUrl",value);message(value?"Backend URL saved on this device.":"Backend URL cleared.","success");});
function safe(value){return String(value ?? "").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function message(text,kind=""){ $("message").textContent=text; $("message").className="message "+kind; }
function scoreReport(data){
 const s=data.summary||{}, total=Number(s.total_issues||0);
 const penalty=Number(s.high||0)*25+Number(s.medium||0)*12+Number(s.low||0)*5+Number(s.info||0)*1;
 const score=Math.max(0,Math.min(100,100-penalty));
 const grade=score>=95?"A":score>=85?"B":score>=70?"C":score>=50?"D":"F";
 $("securityScore").textContent=score+"/100";$("securityGrade").textContent="Grade "+grade;
 $("scoreNote").textContent=total?total+" finding(s) detected. This is an indicative score, not a certification.":"No findings from the checks performed; this is not proof of security.";
}
function history(){
 let items=[];try{items=JSON.parse(localStorage.getItem("bugHunterHistory")||"[]")}catch{}
 $("historyList").innerHTML=items.length?items.slice(0,8).map(x=>'<div class="history-item"><div><b>'+safe(x.title||x.target)+'</b><small>'+safe(new Date(x.checked_at).toLocaleString())+'</small></div><b>'+safe(x.total)+' finding(s)</b></div>').join(""):'<p class="muted tiny">Your recent scans will appear here on this device.</p>';
}
function render(data){
 latestReport=data;$("results").classList.remove("hidden");
 $("resultTitle").textContent=data.page_title || data.target;
 for(const key of ["total_issues","high","medium","low"]){const id={total_issues:"totalCount",high:"highCount",medium:"mediumCount",low:"lowCount"}[key];$(id).textContent=data.summary[key] ?? 0;}
 $("issueList").innerHTML=data.issues.length?data.issues.map(x=>'<article class="issue '+safe(x.severity)+'"><h3>'+safe(x.title)+' · '+safe(x.severity)+'</h3><p>'+safe(x.category)+' — '+safe(x.details)+'</p><p class="fix">Suggested fix: '+safe(x.recommendation)+'</p></article>').join(""):'<article class="issue"><h3>No issues detected by these checks</h3><p>This does not prove the website is vulnerability-free.</p></article>';
 $("linkList").innerHTML=data.links.length?data.links.map(x=>'<div class="link">'+safe(x.url)+' <b>'+(x.status?'HTTP '+safe(x.status):safe(x.error||"Not checked"))+'</b></div>').join(""):'<div class="link">No same-site links available.</div>';
 scoreReport(data);$("downloadJson").disabled=false;$("printReport").disabled=false;
 let items=[];try{items=JSON.parse(localStorage.getItem("bugHunterHistory")||"[]")}catch{}
 items.unshift({target:data.target,title:data.page_title,checked_at:data.checked_at,total:data.summary.total_issues,report:data});
 localStorage.setItem("bugHunterHistory",JSON.stringify(items.slice(0,10)));history();
}
$("scanButton").addEventListener("click",async()=>{
 const url=$("targetUrl").value.trim();
 if(!url)return message("Enter a website URL first.","error");
 if(!$("authorized").checked)return message("Confirm that you own this site or have permission.","error");
 try{const parsed=new URL(url);if(!["http:","https:"].includes(parsed.protocol))throw Error("Only HTTP and HTTPS URLs are supported.");}catch(e){return message(e.message||"Enter a valid URL.","error");}
 if(!API_BASE)return message("Add your deployed backend URL above and tap Save.","error");
 const btn=$("scanButton");btn.disabled=true;btn.textContent="Scanning…";message("Scanning authorized public page…");
 try{const response=await fetch(API_BASE.replace(/\/$/,"")+"/api/scan",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({url,authorized:true})});const data=await response.json();if(!response.ok)throw Error(data.detail||"Scan failed.");render(data);message("Scan complete. Manually verify findings.","success");}
 catch(e){message(e.message||"Could not connect to scanner.","error");}
 finally{btn.disabled=false;btn.innerHTML='Start website scan <span>→</span>';}
});
$("downloadJson").addEventListener("click",()=>{if(!latestReport)return;const blob=new Blob([JSON.stringify(latestReport,null,2)],{type:"application/json"});const u=URL.createObjectURL(blob),a=document.createElement("a");a.href=u;a.download="ai-bug-hunter-report.json";a.click();URL.revokeObjectURL(u);});
$("printReport").addEventListener("click",()=>{if(latestReport)window.print();});
$("emailReport").addEventListener("click",()=>{
 if(!latestReport)return;
 const to=$("emailTo").value.trim();
 if(to && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to)){$("emailMessage").textContent="Enter a valid recipient email address.";return;}
 const d=latestReport,s=d.summary||{};
 const lines=["AI Bug Hunter — Website Scan Report","Website: "+d.target,"Page title: "+(d.page_title||"N/A"),"Scanned: "+d.checked_at,"HTTP status: "+d.http_status,"Findings: "+(s.total_issues||0)+" | High: "+(s.high||0)+" | Medium: "+(s.medium||0)+" | Low: "+(s.low||0)+" | Info: "+(s.info||0),"","Findings:",...(d.issues||[]).map((x,i)=>(i+1)+". ["+x.severity.toUpperCase()+"] "+x.title+" — "+x.details+" Suggested fix: "+x.recommendation),"","Same-site links checked:",...(d.links||[]).map(x=>x.url+" — "+(x.status?"HTTP "+x.status:(x.error||"not checked"))),"","Note: Automated findings are indicators, not proof. Manually verify each result. Scan only systems you own or are authorized to test."];
 const subject="AI Bug Hunter scan report — "+(d.page_title||d.target);
 const href="mailto:"+encodeURIComponent(to)+"?subject="+encodeURIComponent(subject)+"&body="+encodeURIComponent(lines.join("\n"));
 $("emailMessage").textContent="Opening your email app with the report prepared. Review and send it there.";
 window.location.href=href;
});
history();
if ("serviceWorker" in navigator && location.protocol.startsWith("http"))window.addEventListener("load",()=>navigator.serviceWorker.register("./sw.js").catch(()=>{}));
