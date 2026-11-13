// AI Bug Hunter dashboard logic
let API_BASE = localStorage.getItem("bugHunterApiUrl") || "";
const $ = id => document.getElementById(id);
let latestReport = null;
$("apiUrl").value = API_BASE;
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
window.startWebsiteScan=async function(){
 const btn=$("scanButton");
 const url=$("targetUrl").value.trim();
 if(!url){message("Enter a website URL first.","error");return;}
 if(!$("authorized").checked){message("Confirm that you own this site or have permission.","error");return;}
 try{const parsed=new URL(url);if(!["http:","https:"].includes(parsed.protocol))throw Error("Only HTTP and HTTPS URLs are supported.");}catch(e){message(e.message||"Enter a valid URL.","error");return;}
 API_BASE=(localStorage.getItem("bugHunterApiUrl")||"").trim().replace(/\\/$/,"");
 if(!API_BASE){message("Add your deployed backend URL above and tap Save.","error");return;}
 btn.disabled=true;btn.textContent="Scanning…";message("Connecting to backend and scanning. Please wait…");
 try{
  const controller=new AbortController();const timeout=setTimeout(()=>controller.abort(),45000);
  let response;
  try{response=await fetch(API_BASE+"/api/scan",{method:"POST",mode:"cors",cache:"no-store",headers:{"Content-Type":"application/json"},body:JSON.stringify({url,authorized:true}),signal:controller.signal});}
  finally{clearTimeout(timeout);}
  const raw=await response.text();let data;try{data=JSON.parse(raw);}catch{throw Error("Backend returned an unreadable response (HTTP "+response.status+").");}
  if(!response.ok)throw Error(data.detail||("Scan failed (HTTP "+response.status+")."));
  if(!data.summary||!Array.isArray(data.issues)||!Array.isArray(data.links))throw Error("Backend response format is incomplete.");
  render(data);message("Scan complete. Manually verify findings.","success");
 }catch(e){
  const reason=e.name==="AbortError"?"Scan timed out after 45 seconds. Try again.":(e.message||"Could not connect to scanner.");
  message(reason,"error");
 }finally{btn.disabled=false;btn.innerHTML='Start website scan <span>→</span>';}
};
$("downloadJson").addEventListener("click",()=>{if(!latestReport)return;const blob=new Blob([JSON.stringify(latestReport,null,2)],{type:"application/json"});const u=URL.createObjectURL(blob),a=document.createElement("a");a.href=u;a.download="ai-bug-hunter-report.json";a.click();URL.revokeObjectURL(u);});
$("printReport").addEventListener("click",()=>{if(latestReport)window.print();});
$("emailReport").addEventListener("click",()=>{
 if(!latestReport)return;
 const to=$("emailTo").value.trim();
 if(to && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to)){$("emailMessage").textContent="Enter a valid recipient email address.";return;}
 const d=latestReport,s=d.summary||{}, issues=d.issues||[], links=d.links||[];
 const score=$("securityScore").textContent||"Not calculated";
 const grade=$("securityGrade").textContent||"Not graded";
 const date=d.checked_at?new Date(d.checked_at).toLocaleString():"Not available";
 const domain=(()=>{try{return new URL(d.target).hostname}catch{return d.target||"the submitted website"}})();
 const severityCount=["high","medium","low","info"].map(k=>k[0].toUpperCase()+k.slice(1)+": "+(s[k]||0)).join(" | ");
 const priority={"high":"Immediate review","medium":"Prioritize remediation","low":"Address during hardening","info":"Review for quality"};
 const lines=[
 "CONFIDENTIAL — WEBSITE SECURITY & QUALITY ASSESSMENT",
 "AI BUG HUNTER | AUTOMATED SCAN REPORT",
 "",
 "1. EXECUTIVE SUMMARY",
 "Target: "+(d.target||"N/A"),
 "Page title: "+(d.page_title||"N/A"),
 "Assessment date: "+date,
 "HTTP response: "+(d.http_status||"Not available"),
 "Total findings: "+(s.total_issues||issues.length),
 severityCount,
 "Indicative security score: "+score+" ("+grade+")",
 "",
 "Assessment overview: This report summarizes the results of a lightweight, non-invasive automated review. Findings are preliminary indicators and should be validated by a qualified reviewer.",
 "",
 "2. FINDINGS AND RECOMMENDED ACTIONS",
 ...(issues.length?issues.map((x,i)=>[
 (i+1)+". "+String(x.title||"Untitled finding").toUpperCase(),
 "   Severity: "+String(x.severity||"Unclassified").toUpperCase()+" — "+(priority[String(x.severity||"").toLowerCase()]||"Review"),
 "   Category: "+(x.category||"General"),
 "   Observation: "+(x.details||"No additional details supplied."),
 "   Recommended remediation: "+(x.recommendation||"Review the affected configuration and apply an appropriate fix."),
 ""] .join("\n")):["No findings were returned by the checks performed. This does not establish that the website is free of vulnerabilities.",""],
 "3. SAME-SITE LINK CHECK",
 ...(links.length?links.map((x,i)=>(i+1)+". "+x.url+" — "+(x.status?"HTTP "+x.status:(x.error||"Not checked"))):["No same-site links were available for sampling."]),
 "",
 "4. SCOPE AND METHODOLOGY",
 "The scan was limited to the submitted public page and the checks displayed by this early-development version of AI Bug Hunter, including HTTP response, selected security headers, basic HTML quality, basic form signals, sampled same-site links and mixed-content indicators.",
 "This scan does not perform exploitation, authenticated testing, source-code review, infrastructure testing or a comprehensive penetration test.",
 "",
 "5. RECOMMENDED NEXT STEPS",
 "• Validate each observation manually before treating it as a confirmed vulnerability.",
 "• Prioritize High and Medium findings, then apply and test the recommended fixes.",
 "• Re-scan after remediation and retain evidence of the changes.",
 "",
 "6. IMPORTANT LIMITATIONS",
 "The score and letter grade are heuristic indicators based only on findings from this scan; they are not a certification, compliance assessment or guarantee of security. False positives and missed issues are possible. The assessment should only be performed on systems owned by the recipient or where explicit authorization has been granted.",
 "",
 "Prepared by: AI Bug Hunter",
 "Report generated: "+new Date().toLocaleString(),
 "End of report"
 ];
 const subject="[Website Security Report] "+domain+" — "+(s.total_issues||issues.length)+" finding(s)";
 const href="mailto:"+encodeURIComponent(to)+"?subject="+encodeURIComponent(subject)+"&body="+encodeURIComponent(lines.join("\n"));
 $("emailMessage").textContent="A professional report draft is being opened in your email app. Please review the recipient and report, then send it.";
 window.location.href=href;
});
history();
if ("serviceWorker" in navigator && location.protocol.startsWith("http"))window.addEventListener("load",()=>navigator.serviceWorker.register("./sw.js").catch(()=>{}));

const apiStatus=$("apiMessage");
if(API_BASE&&apiStatus){apiStatus.textContent="Saved backend URL: "+API_BASE;apiStatus.className="message";}
