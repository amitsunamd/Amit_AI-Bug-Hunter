// Set this to your deployed API URL after backend hosting.
const API_BASE = "";
const $ = id => document.getElementById(id);
let latestReport = null;
function safe(value){return String(value ?? "").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function message(text,kind=""){ $("message").textContent=text; $("message").className="message "+kind; }
function render(data){
 latestReport=data;$("results").classList.remove("hidden");
 $("resultTitle").textContent=data.page_title || data.target;
 for(const key of ["total_issues","high","medium","low"]){
  const id={total_issues:"totalCount",high:"highCount",medium:"mediumCount",low:"lowCount"}[key];
  $(id).textContent=data.summary[key] ?? 0;
 }
 $("issueList").innerHTML=data.issues.length?data.issues.map(x=>'<article class="issue '+safe(x.severity)+'"><h3>'+safe(x.title)+' · '+safe(x.severity)+'</h3><p>'+safe(x.category)+' — '+safe(x.details)+'</p><p class="fix">Suggested fix: '+safe(x.recommendation)+'</p></article>').join(""):'<article class="issue"><h3>No issues detected by these checks</h3><p>This does not prove the website is vulnerability-free.</p></article>';
 $("linkList").innerHTML=data.links.length?data.links.map(x=>'<div class="link">'+safe(x.url)+' <b>'+(x.status?'HTTP '+safe(x.status):safe(x.error||"Not checked"))+'</b></div>').join(""):'<div class="link">No same-site links available.</div>';
 $("downloadJson").disabled=false;
}
$("scanButton").addEventListener("click",async()=>{
 const url=$("targetUrl").value.trim();
 if(!url)return message("Enter a website URL first.","error");
 if(!$("authorized").checked)return message("Confirm that you own this site or have permission.","error");
 try{const parsed=new URL(url);if(!["http:","https:"].includes(parsed.protocol))throw Error("Only HTTP and HTTPS URLs are supported.");}catch(e){return message(e.message||"Enter a valid URL.","error");}
 if(!API_BASE)return message("Backend is not deployed yet. Dashboard is ready; connect the API URL in frontend/app.js after hosting.","error");
 const btn=$("scanButton");btn.disabled=true;btn.textContent="Scanning…";message("Scanning authorized public page…");
 try{
  const response=await fetch(API_BASE.replace(/\/$/,"")+"/api/scan",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({url,authorized:true})});
  const data=await response.json();if(!response.ok)throw Error(data.detail||"Scan failed.");
  render(data);message("Scan complete. Manually verify findings.","success");
 }catch(e){message(e.message||"Could not connect to scanner.","error");}
 finally{btn.disabled=false;btn.innerHTML='Start website scan <span>→</span>';}
});
$("downloadJson").addEventListener("click",()=>{
 if(!latestReport)return;
 const blob=new Blob([JSON.stringify(latestReport,null,2)],{type:"application/json"});
 const u=URL.createObjectURL(blob),a=document.createElement("a");a.href=u;a.download="ai-bug-hunter-report.json";a.click();URL.revokeObjectURL(u);
});
