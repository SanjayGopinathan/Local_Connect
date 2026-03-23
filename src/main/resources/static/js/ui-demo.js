const users=["riya_dev","arjun_kiran","mei_lin","sam_p"];
const groups=["backend-squad","infra-team","design-sync"];

const userList=document.getElementById("userList");
const groupList=document.getElementById("groupList");

users.forEach(u=>{
let div=document.createElement("div");
div.className="user";
div.innerText=u;
userList.appendChild(div);
});

groups.forEach(g=>{
let div=document.createElement("div");
div.className="group";
div.innerText=g;
groupList.appendChild(div);
});

/* DEMO CHAT */

function addMsg(text,side){
let div=document.createElement("div");
div.className="msg "+side;
div.innerText=text;
document.getElementById("messages").appendChild(div);
}

addMsg("can you check socket issue?","left");
addMsg("fixed heartbeat issue","right");

document.getElementById("sendBtn").onclick=()=>{
let val=msgInput.value;
if(!val) return;
addMsg(val,"right");
msgInput.value="";
}
function triggerFile(){
document.getElementById("fileInput").click();
}