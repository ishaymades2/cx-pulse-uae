import { hasPermission } from "./permissions.js";

const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{"Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store","X-Content-Type-Options":"nosniff"}});
const id=()=>crypto.randomUUID();
const now=()=>Math.floor(Date.now()/1000);
async function body(req){try{const b=await req.json();return b&&typeof b==="object"&&!Array.isArray(b)?b:null}catch{return null}}
const str=(v,max=2000)=>typeof v==="string"?v.trim().slice(0,max):"";
const allowed=(u,p)=>hasPermission(u,p);
async function audit(db,u,action,details={}){await db.prepare("INSERT INTO audit_log(id,actor_id,action,details_json,created_at) VALUES(?,?,?,?,?)").bind(id(),u.id,action,JSON.stringify(details),now()).run()}
function denied(){return json({error:"You do not have permission to perform this action."},403)}
export async function handleEnterpriseApi(req,user,env){
 const url=new URL(req.url),p=url.pathname,m=req.method.toUpperCase(),db=env.DB;
 if(!db)return json({error:"Database unavailable."},503);
 if(p==="/api/analytics"&&m==="GET"){
  if(!allowed(user,"reports.view_all")&&!allowed(user,"reports.view_team")&&!allowed(user,"reports.view_own"))return denied();
  const scope=user.isOwner||user.role==="admin"?"all":user.accessRole==="supervisor"?"team":"own";
  const rows=scope==="all"?await db.prepare("SELECT status,priority,category,created_at,updated_at,team FROM cases").all():scope==="team"?await db.prepare("SELECT status,priority,category,created_at,updated_at,team FROM cases WHERE team=?").bind(user.assignedTeam||"").all():await db.prepare("SELECT status,priority,category,created_at,updated_at,team FROM cases WHERE created_by=? OR assigned_to=?").bind(user.id,user.id).all();
  const data=rows.results||[],count=s=>data.filter(x=>x.status===s).length,byCategory={};
  for(const x of data)byCategory[x.category]=(byCategory[x.category]||0)+1;
  const resolved=data.filter(x=>x.status==="Resolved");
  return json({scope,total:data.length,open:count("Open"),inProgress:count("In progress"),resolved:resolved.length,urgent:data.filter(x=>x.priority==="Urgent").length,resolutionRate:data.length?Math.round(resolved.length/data.length*1000)/10:0,byCategory,monthly:Array.from({length:12},(_,i)=>({month:i+1,created:data.filter(x=>new Date(x.created_at*1000).getMonth()===i).length}))});
 }
 if(p==="/api/customers"&&(m==="GET"||m==="POST")){
  if(!allowed(user,"customers.view")&&!(m==="POST"&&allowed(user,"customers.manage")))return denied();
  if(m==="GET"){const q=await db.prepare("SELECT id,name,email,phone,segment,notes,created_at,updated_at FROM customers ORDER BY updated_at DESC LIMIT 500").all();return json({customers:q.results||[]})}
  if(!allowed(user,"customers.manage"))return denied();const b=await body(req);if(!b)return json({error:"Invalid JSON."},400);
  const name=str(b.name,100),email=str(b.email,254),phone=str(b.phone,40),segment=str(b.segment,40)||"Standard",notes=str(b.notes,2000);
  if(name.length<2)return json({error:"Customer name is required."},400);
  const cid=id(),t=now();await db.prepare("INSERT INTO customers(id,name,email,phone,segment,notes,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)").bind(cid,name,email,phone,segment,notes,user.id,t,t).run();await audit(db,user,"customer.created",{customerId:cid});return json({id:cid},201);
 }
 if(p.startsWith("/api/customers/")&&m==="PATCH"){
  if(!allowed(user,"customers.manage"))return denied();const cid=p.split("/").pop(),b=await body(req);if(!b)return json({error:"Invalid JSON."},400);
  const current=await db.prepare("SELECT id FROM customers WHERE id=?").bind(cid).first();if(!current)return json({error:"Customer not found."},404);
  await db.prepare("UPDATE customers SET name=?,email=?,phone=?,segment=?,notes=?,updated_at=? WHERE id=?").bind(str(b.name,100),str(b.email,254),str(b.phone,40),str(b.segment,40)||"Standard",str(b.notes,2000),now(),cid).run();await audit(db,user,"customer.updated",{customerId:cid});return json({ok:true});
 }
 if(p==="/api/tasks"&&(m==="GET"||m==="POST")){
  if(m==="GET"){if(!allowed(user,"tasks.view_all")&&!allowed(user,"tasks.view_team")&&!allowed(user,"tasks.view_own"))return denied();let q;if(user.isOwner||user.role==="admin"||allowed(user,"tasks.view_all"))q=await db.prepare("SELECT * FROM tasks ORDER BY COALESCE(due_at,9999999999),created_at DESC LIMIT 500").all();else if(user.accessRole==="supervisor")q=await db.prepare("SELECT * FROM tasks WHERE team=? ORDER BY due_at").bind(user.assignedTeam||"").all();else q=await db.prepare("SELECT * FROM tasks WHERE assigned_to=? OR created_by=? ORDER BY due_at").bind(user.id,user.id).all();return json({tasks:q.results||[]})}
  if(!allowed(user,"tasks.manage")&&!allowed(user,"tasks.manage_team")&&!allowed(user,"tasks.update_own"))return denied();const b=await body(req);if(!b)return json({error:"Invalid JSON."},400);const title=str(b.title,160);if(title.length<2)return json({error:"Task title is required."},400);
  const tid=id(),t=now(),team=user.accessRole==="supervisor"?(user.assignedTeam||""):str(b.team,100);const assignee=str(b.assignedTo,80)||null;
  if(user.accessRole==="supervisor"&&team!==(user.assignedTeam||""))return denied();
  await db.prepare("INSERT INTO tasks(id,title,description,status,priority,assigned_to,team,due_at,created_by,created_at,updated_at) VALUES(?,?,?,'Open',?,?,?,?,?,?,?)").bind(tid,title,str(b.description),["Low","Normal","High","Urgent"].includes(b.priority)?b.priority:"Normal",assignee,team,Number.isFinite(Number(b.dueAt))&&b.dueAt?Number(b.dueAt):null,user.id,t,t).run();await audit(db,user,"task.created",{taskId:tid});if(assignee)await db.prepare("INSERT INTO notifications(id,user_id,title,body,kind,link,created_at) VALUES(?,?,?,?,?,?,?)").bind(id(),assignee,"New task assigned",title,"task","/tasks",t).run();return json({id:tid},201);
 }
 if(p.startsWith("/api/tasks/")&&m==="PATCH"){
  const tid=p.split("/").pop(),b=await body(req);if(!b)return json({error:"Invalid JSON."},400);const row=await db.prepare("SELECT * FROM tasks WHERE id=?").bind(tid).first();if(!row)return json({error:"Task not found."},404);
  const can=allowed(user,"tasks.manage")||allowed(user,"tasks.manage_team")&&row.team===user.assignedTeam||allowed(user,"tasks.update_own")&&(row.assigned_to===user.id||row.created_by===user.id);if(!can)return denied();
  const status=["Open","In progress","Done","Cancelled"].includes(b.status)?b.status:row.status;await db.prepare("UPDATE tasks SET status=?,updated_at=? WHERE id=?").bind(status,now(),tid).run();await audit(db,user,"task.updated",{taskId:tid,status});return json({ok:true});
 }
 if(p==="/api/notifications"&&m==="GET"){if(!allowed(user,"notifications.view"))return denied();const q=await db.prepare("SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 100").bind(user.id).all();return json({notifications:q.results||[]})}
 if(p.startsWith("/api/notifications/")&&m==="PATCH"){const nid=p.split("/").pop();await db.prepare("UPDATE notifications SET read_at=? WHERE id=? AND user_id=?").bind(now(),nid,user.id).run();return json({ok:true})}
 if(p==="/api/knowledge"&&(m==="GET"||m==="POST")){
  if(!allowed(user,"knowledge.view")&&!allowed(user,"knowledge.manage"))return denied();
  if(m==="GET"){const q=await db.prepare("SELECT id,title,category,body,status,author_id,created_at,updated_at FROM knowledge_articles WHERE status='Published' OR ?=1 ORDER BY updated_at DESC LIMIT 300").bind(allowed(user,"knowledge.manage")?1:0).all();return json({articles:q.results||[]})}
  if(!allowed(user,"knowledge.manage"))return denied();const b=await body(req);if(!b)return json({error:"Invalid JSON."},400);const title=str(b.title,160),article=str(b.body,12000);if(title.length<3||article.length<10)return json({error:"Enter an article title and content."},400);const aid=id(),t=now();await db.prepare("INSERT INTO knowledge_articles(id,title,category,body,status,author_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)").bind(aid,title,str(b.category,80)||"General",article,b.status==="Published"?"Published":"Draft",user.id,t,t).run();await audit(db,user,"knowledge.created",{articleId:aid});return json({id:aid},201);
 }
 if(p==="/api/feedback"&&(m==="GET"||m==="POST")){
  if(m==="GET"&&!allowed(user,"feedback.view")&&!allowed(user,"feedback.view_team"))return denied();
  if(m==="GET"){const q=await db.prepare("SELECT * FROM feedback ORDER BY created_at DESC LIMIT 500").all();return json({feedback:q.results||[]})}
  if(!allowed(user,"feedback.create")&&!allowed(user,"feedback.manage"))return denied();const b=await body(req);if(!b)return json({error:"Invalid JSON."},400);const rating=Number(b.rating);if(!Number.isInteger(rating)||rating<1||rating>5)return json({error:"Rating must be between 1 and 5."},400);const fid=id();await db.prepare("INSERT INTO feedback(id,case_id,customer_name,rating,comment,channel,created_by,created_at) VALUES(?,?,?,?,?,?,?,?)").bind(fid,str(b.caseId,80)||null,str(b.customerName,100),rating,str(b.comment,2000),str(b.channel,40)||"Internal",user.id,now()).run();await audit(db,user,"feedback.created",{feedbackId:fid,rating});return json({id:fid},201);
 }
 if(p==="/api/teams"&&(m==="GET"||m==="POST")){
  if(m==="GET"){if(!allowed(user,"teams.view"))return denied();const q=await db.prepare("SELECT t.*,u.display_name AS manager_name FROM teams t LEFT JOIN users u ON u.id=t.manager_id ORDER BY t.name").all();return json({teams:q.results||[]})}
  if(!allowed(user,"teams.manage"))return denied();const b=await body(req);if(!b)return json({error:"Invalid JSON."},400);const name=str(b.name,100);if(name.length<2)return json({error:"Team name required."},400);const tid=id(),t=now();try{await db.prepare("INSERT INTO teams(id,name,description,manager_id,created_at,updated_at) VALUES(?,?,?,?,?,?)").bind(tid,name,str(b.description,500),str(b.managerId,80)||null,t,t).run()}catch{return json({error:"Team already exists or manager is invalid."},409)}await audit(db,user,"team.created",{teamId:tid});return json({id:tid},201);
 }
 if(p==="/api/owner/overview"&&m==="GET"){
  if(!user.isOwner)return denied();const [staff,cases,approvals,tasks,notes]=await Promise.all([db.prepare("SELECT COUNT(*) total,SUM(is_active) active FROM users").first(),db.prepare("SELECT COUNT(*) total FROM cases").first(),db.prepare("SELECT COUNT(*) total FROM owner_approval_requests WHERE status='pending'").first(),db.prepare("SELECT COUNT(*) total FROM tasks WHERE status!='Done'").first(),db.prepare("SELECT COUNT(*) total FROM employee_notes").first()]);return json({staff:staff?.total||0,activeStaff:staff?.active||0,cases:cases?.total||0,pendingApprovals:approvals?.total||0,openTasks:tasks?.total||0,notes:notes?.total||0});
 }
 if(p==="/api/owner/approvals"&&(m==="GET"||m==="POST")){
  if(!user.isOwner)return denied();if(m==="GET"){const q=await db.prepare("SELECT a.*,u.email,u.display_name FROM owner_approval_requests a JOIN users u ON u.id=a.requester_id ORDER BY a.created_at DESC LIMIT 200").all();return json({requests:q.results||[]})}
  const b=await body(req);if(!b)return json({error:"Invalid JSON."},400);const row=await db.prepare("SELECT * FROM owner_approval_requests WHERE id=?").bind(str(b.id,80)).first();if(!row||row.status!=="pending")return json({error:"Pending request not found."},404);const decision=b.decision==="approved"?"approved":b.decision==="rejected"?"rejected":"";if(!decision)return json({error:"Invalid decision."},400);await db.prepare("UPDATE owner_approval_requests SET status=?,reviewed_by=?,review_note=?,reviewed_at=? WHERE id=?").bind(decision,user.id,str(b.note,1000),now(),row.id).run();await audit(db,user,"owner_approval."+decision,{requestId:row.id,type:row.request_type});return json({ok:true});
 }
 if(p==="/api/owner/backup"&&m==="POST"){
  if(!user.isOwner)return denied();const snapshot={createdAt:now(),tables:{}};for(const table of ["users","cases","customers","tasks","teams","knowledge_articles","feedback","approval_requests","owner_approval_requests","employee_notes","system_settings","integration_settings"]){const q=await db.prepare("SELECT * FROM "+table).all();snapshot.tables[table]=q.results||[]}const bid=id();await db.prepare("INSERT INTO system_backup_log(id,created_by,backup_type,status,details_json,created_at) VALUES(?,?,?,'completed',?,?)").bind(bid,user.id,"json-export",JSON.stringify({tables:Object.keys(snapshot.tables)}),now()).run();await audit(db,user,"backup.exported",{backupId:bid});return json(snapshot);
 }
 if(p==="/api/owner/audit"&&m==="GET"){if(!user.isOwner)return denied();const q=await db.prepare("SELECT a.*,u.email,u.display_name FROM audit_log a JOIN users u ON u.id=a.actor_id ORDER BY a.created_at DESC LIMIT 500").all();return json({events:q.results||[]})}
 if(p==="/api/owner/settings"&&(m==="GET"||m==="POST")){
  if(!user.isOwner)return denied();if(m==="GET"){const q=await db.prepare("SELECT * FROM system_settings ORDER BY setting_key").all();return json({settings:q.results||[]})}
  const b=await body(req);if(!b)return json({error:"Invalid JSON."},400);const key=str(b.key,100),value=str(b.value,500);if(!["allow_new_cases","default_case_team","case_export_enabled"].includes(key))return json({error:"Unsupported setting."},400);await db.prepare("INSERT INTO system_settings(setting_key,setting_value,updated_by,updated_at) VALUES(?,?,?,?) ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value,updated_by=excluded.updated_by,updated_at=excluded.updated_at").bind(key,value,user.id,now()).run();await audit(db,user,"owner.setting_updated",{key,value});return json({ok:true});
 }
 if(p==="/api/owner/request-approval"&&m==="POST"){
  const b=await body(req);if(!b)return json({error:"Invalid JSON."},400);const type=str(b.type,80),reason=str(b.reason,1000);if(!["sensitive_setting","staff_role","account_change","data_restore","integration_change","ownership_change"].includes(type)||reason.length<8)return json({error:"Approval type and reason required."},400);const aid=id();await db.prepare("INSERT INTO owner_approval_requests(id,requester_id,request_type,payload_json,reason,created_at) VALUES(?,?,?,?,?,?)").bind(aid,user.id,type,JSON.stringify(b.payload||{}),reason,now()).run();await audit(db,user,"owner_approval.requested",{requestId:aid,type});return json({id:aid},201);
 }
 return null;
}
