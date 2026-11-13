// AI Bug Hunter — dashboard and report manager
function storageGet(key, fallback=""){try{return localStorage.getItem(key) ?? fallback;}catch(e){return fallback;}}
function storageSet(key, value){try{return localStorage.setItem(key,value),true;}catch(e){return false;}}
let API_BASE = storageGet("bugHunterApiUrl", "");
const $ = id => document.getElementById(id);
let latestReport = null;
$("apiUrl").value = API_BASE;

function safe(value){return String(value ?? "").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function message(text,kind=""){ $("message").textContent=text; $("message").className="message "+kind; }

const FIX_GUIDES = {
 "security headers": "Configure this header at the web server, reverse proxy or CDN. Test the policy in staging first; overly strict settings can break legitimate site features.",
 "availability": "Check server and application logs, hosting health, DNS, TLS and upstream dependencies. Confirm the route returns the intended status and add monitoring.",
 "html quality": "Add a concise, unique page title that describes the page. Keep it useful to visitors and avoid keyword stuffing.",
 "seo": "Add a concise, page-specific meta description in the HTML head. It should accurately summarize the page content.",
 "accessibility": "Add meaningful alt text to informative images. Use alt=\"\" for decorative images so screen readers can skip them.",
 "transport security": "Serve the entire site over HTTPS, redirect HTTP to HTTPS, renew certificates automatically and enable HSTS only after HTTPS is reliable.",
 "form security": "Submit credentials using POST over HTTPS. Never place passwords or sensitive data in query strings; add CSRF protection and server-side validation.",
 "mixed content": "Replace HTTP resource URLs with HTTPS equivalents. If a provider does not support HTTPS, remove or replace that resource.",
 "broken link": "Open the destination, confirm the intended page, then update the href or restore the missing route. Add redirects only when the destination has genuinely moved."
};
function detailedFix(issue){
 const category=String(issue.category||"").toLowerCase();
 const matched=Object.keys(FIX_GUIDES).find(k=>category.includes(k));
 return matched ? FIX_GUIDES[matched] : "Review the affected URL or component, reproduce the observation manually, apply the least-privilege configuration change, then re-run the scan to verify the result.";
}
function scoreReport(data){
 const s=data.summary||{}, total=Number(s.total_issues||0);
 const penalty=Number(s.high||0)*25+Number(s.medium||0)*12+Number(s.low||0)*5+Number(s.info||0);
 const score=Math.max(0,Math.min(100,100-penalty));
 const grade=score>=95?"A":score>=85?"B":score>=70?"C":score>=50?"D":"F";
 $("securityScore").textContent=score+"/100";$("securityGrade").textContent="Grade "+grade;
 $("scoreNote").textContent=total?total+" finding(s). Heuristic score only; not a certification or proof of security.":"No findings in the checks performed; this is not proof of security.";
}
function getHistory(){try{return JSON.parse(storageGet("bugHunterHistory","[]"))}catch(e){return []}}
function saveReport(data){
 latestReport=data;
 storageSet("bugHunterLastReport",JSON.stringify(data));
 const items=getHistory();
 const key=data.checked_at||new Date().toISOString();
 const filtered=items.filter(x=>x.checked_at!==key || x.target!==data.target);
 filtered.unshift({target:data.target,title:data.page_title,checked_at:key,total:(data.summary||{}).total_issues??(data.issues||[]).length,report:data});
 storageSet("bugHunterHistory",JSON.stringify(filtered.slice(0,20)));
 renderHistory();
}
function renderHistory(){
 const items=getHistory();
 $("historyList").innerHTML=items.length?items.slice(0,12).map((x,i)=>'<button type="button" class="history-item" data-history-index="'+i+'"><span><b>'+safe(x.title||x.target)+'</b><small>'+safe(x.target||"")+' · '+safe(new Date(x.checked_at).toLocaleString())+'</small></span><b>'+safe(x.total)+' finding(s)</b></button>').join(""):'<p class="muted tiny">Your recent scans will appear here on this device.</p>';
}
function render(data){
 latestReport=data;
 $("results").classList.remove("hidden");
 $("resultTitle").textContent=data.page_title||data.target||"Website Security Assessment";
 const s=data.summary||{}, issues=data.issues||[], links=data.links||[];
 $("totalCount").textContent=s.total_issues??issues.length;
 $("highCount").textContent=s.high??0;$("mediumCount").textContent=s.medium??0;$("lowCount").textContent=s.low??0;
 $("issueList").innerHTML=issues.length?issues.map(x=>'<article class="issue '+safe(x.severity)+'"><h3>'+safe(String(x.title||"Finding"))+' · '+safe(x.severity||"Unclassified")+'</h3><p><b>Category:</b> '+safe(x.category||"General")+'</p><p><b>Observation:</b> '+safe(x.details||"No further detail supplied.")+'</p><p class="fix"><b>Recommended remediation:</b> '+safe(x.recommendation||"Review the affected configuration.")+'</p><p class="fix"><b>Implementation guidance:</b> '+safe(detailedFix(x))+'</p><p class="tiny muted">Validate manually before treating this as a confirmed vulnerability.</p></article>').join(""):'<article class="issue"><h3>No issues detected by the checks performed</h3><p>This does not prove the website is vulnerability-free.</p></article>';
 $("linkList").innerHTML=links.length?links.map(x=>'<div class="link">'+safe(x.url)+' <b>'+(x.status?'HTTP '+safe(x.status):safe(x.error||"Not checked"))+'</b></div>').join(""):'<div class="link">No same-site links available.</div>';
 scoreReport(data);$("downloadJson").disabled=false;$("printReport").disabled=false;
}
function restore(){
 const raw=storageGet("bugHunterLastReport","");
 if(raw){try{const data=JSON.parse(raw);render(data);message("Previous scan report restored from this device.","success");}catch(e){console.warn("Saved report could not be restored",e);}}
 renderHistory();
}
window.startWebsiteScan=async function(){
 const btn=$("scanButton"), url=$("targetUrl").value.trim();
 if(!url){message("Enter a website URL first.","error");return;}
 if(!$("authorized").checked){message("Confirm that you own this site or have permission.","error");return;}
 try{const parsed=new URL(url);if(!["http:","https:"].includes(parsed.protocol))throw Error("Only HTTP and HTTPS URLs are supported.");}catch(e){message(e.message||"Enter a valid URL.","error");return;}
 API_BASE=($("apiUrl").value.trim()||storageGet("bugHunterApiUrl","")).replace(/\/$/,"");
 if(!API_BASE){message("Add your deployed backend URL and tap Save.","error");return;}
 btn.disabled=true;btn.textContent="Scanning…";message("Connecting to backend and scanning. Please wait…");
 try{
  const controller=new AbortController(), timeout=setTimeout(()=>controller.abort(),45000);
  let response;
  try{response=await fetch(API_BASE+"/api/scan",{method:"POST",mode:"cors",cache:"no-store",headers:{"Content-Type":"application/json"},body:JSON.stringify({url,authorized:true}),signal:controller.signal});}
  finally{clearTimeout(timeout);}
  const raw=await response.text();let data;try{data=JSON.parse(raw);}catch(e){throw Error("Backend returned an unreadable response (HTTP "+response.status+").");}
  if(!response.ok)throw Error(data.detail||("Scan failed (HTTP "+response.status+")."));
  if(!data.summary||!Array.isArray(data.issues)||!Array.isArray(data.links))throw Error("Backend response format is incomplete.");
  saveReport(data);render(data);message("Scan complete. Report saved on this device.","success");
 }catch(e){message(e.name==="AbortError"?"Scan timed out after 45 seconds. Try again.":(e.message||"Could not connect to scanner."),"error");}
 finally{btn.disabled=false;btn.innerHTML='Start website scan <span>→</span>';}
};
$("historyList").addEventListener("click",e=>{
 const button=e.target.closest("[data-history-index]");if(!button)return;
 const item=getHistory()[Number(button.dataset.historyIndex)];
 if(item&&item.report){render(item.report);message("Selected saved scan report.","success");window.scrollTo({top:$("results").offsetTop-80,behavior:"smooth"});}
});
$("downloadJson").addEventListener("click",()=>{
 if(!latestReport)return;
 const blob=new Blob([JSON.stringify(latestReport,null,2)],{type:"application/json"});
 const u=URL.createObjectURL(blob),a=document.createElement("a");a.href=u;a.download="ai-bug-hunter-assessment.json";a.click();URL.revokeObjectURL(u);
});
$("printReport").addEventListener("click",()=>{if(latestReport)window.print();});
$("emailReport").addEventListener("click",()=>{
 if(!latestReport)return;
 const to=$("emailTo").value.trim();
 if(!to||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to)){$("emailMessage").textContent="Enter a valid recipient email address.";return;}
 const d=latestReport,s=d.summary||{},issues=d.issues||[],links=d.links||[];
 const score=$("securityScore").textContent,grade=$("securityGrade").textContent;
 const date=d.checked_at?new Date(d.checked_at).toLocaleString():"Not available";
 const domain=(()=>{try{return new URL(d.target).hostname}catch(e){return d.target||"website"}})();
 const severity=["high","medium","low","info"].map(k=>k.toUpperCase()+": "+(s[k]||0)).join(" | ");
 const lines=[
 "CONFIDENTIAL — PROFESSIONAL WEBSITE SECURITY ASSESSMENT",
 "Prepared by AI Bug Hunter",
 "",
 "1. EXECUTIVE SUMMARY",
 "Assessed website: "+(d.target||"N/A"),
 "Page title: "+(d.page_title||"N/A"),
 "Assessment date (UTC): "+date,
 "HTTP response status: "+(d.http_status||"Not available"),
 "Total observations: "+(s.total_issues??issues.length),
 "Finding distribution: "+severity,
 "Indicative security score: "+score+" | "+grade,
 "",
 "Executive assessment: This report records the results of an authorized, lightweight, non-invasive automated review of the publicly accessible page and a limited sample of same-site links. Findings are observations requiring manual validation, not confirmed exploitability.",
 "",
 "2. FINDINGS, RISK AND REMEDIATION",
 ];
 if(issues.length){
  issues.forEach((x,i)=>lines.push([
   "Finding "+(i+1)+": "+String(x.title||"Untitled").toUpperCase(),
   "Severity: "+String(x.severity||"Unclassified").toUpperCase(),
   "Category: "+(x.category||"General"),
   "Observation: "+(x.details||"No detail provided."),
   "Recommended action: "+(x.recommendation||"Review and remediate the affected configuration."),
   "Implementation guidance: "+detailedFix(x),
   "Validation: Re-test the affected page/configuration after remediation.",
   ""
  ].join("\\n")));
 }else{
  lines.push("No findings were returned by the checks performed. This does not establish that the website is free of security weaknesses.","");
 }
 lines.push("3. LINK AVAILABILITY SAMPLE");
 if(links.length){
  links.forEach((x,i)=>lines.push((i+1)+". "+x.url+" — "+(x.status?"HTTP "+x.status:(x.error||"Not checked"))));
 }else{
  lines.push("No same-site links were available for sampling.");
 }
 lines.push("",
 "4. SCOPE AND METHODOLOGY",
 "Checks included HTTP response status, selected security headers, basic HTML title/meta description and image-alt checks, basic password-form signals, mixed-content indicators and a limited sample of same-host links.",
 "The scan did not perform exploitation, authenticated testing, source-code review, infrastructure assessment, configuration auditing or a comprehensive penetration test.",
 "",
 "5. PRIORITIZED ACTION PLAN",
 "1) Validate all High and Medium observations immediately.",
 "2) Assign an owner and target date for each confirmed issue.",
 "3) Apply changes in a test environment and check for regressions.",
 "4) Re-run the assessment and retain before/after evidence.",
 "",
 "6. SCORE INTERPRETATION",
 "The score is a simple heuristic based on finding severity counts. Grade bands: A 95–100; B 85–94; C 70–84; D 50–69; F below 50. It is not a recognized certification, compliance rating or guarantee of security.",
 "",
 "7. LIMITATIONS AND AUTHORIZATION",
 "Automated checks can produce false positives and miss issues. Results must be reviewed by a qualified person. This report is intended only for systems owned by the recipient or explicitly authorized for testing.",
 "",
 "Prepared by: AI Bug Hunter",
 "Generated: "+new Date().toLocaleString(),
 "END OF REPORT"
 ];
 const subject="[Confidential Website Security Assessment] "+domain+" — "+(s.total_issues??issues.length)+" observation(s)";
 const href="mailto:"+encodeURIComponent(to)+"?subject="+encodeURIComponent(subject)+"&body="+encodeURIComponent(lines.join("\n"));
 $("emailMessage").textContent="Professional assessment draft prepared. Review it in your email app and send it manually.";
 window.location.href=href;
});
restore();
// Service worker disabled to prevent stale scanner JavaScript from being cached.
const apiStatus=$("apiMessage");
if(API_BASE&&apiStatus){apiStatus.textContent="Saved backend URL: "+API_BASE;apiStatus.className="message";}
