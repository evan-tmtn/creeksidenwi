window._EV=function(a,b,c){"use strict";var d={_keyStr:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=",encode:function(a){var b,c,e,f,g,h,i,j="",k=0;for(a=d._utf8_encode(a);k<a.length;)b=a.charCodeAt(k++),c=a.charCodeAt(k++),e=a.charCodeAt(k++),f=b>>2,g=(3&b)<<4|c>>4,h=(15&c)<<2|e>>6,i=63&e,isNaN(c)?h=i=64:isNaN(e)&&(i=64),j=j+this._keyStr.charAt(f)+this._keyStr.charAt(g)+this._keyStr.charAt(h)+this._keyStr.charAt(i);return j},_utf8_encode:function(a){a=a.replace(/\r\n/g,"\n");for(var b="",c=0;c<a.length;c++){var d=a.charCodeAt(c);d<128?b+=String.fromCharCode(d):d>127&&d<2048?(b+=String.fromCharCode(d>>6|192),b+=String.fromCharCode(63&d|128)):(b+=String.fromCharCode(d>>12|224),b+=String.fromCharCode(d>>6&63|128),b+=String.fromCharCode(63&d|128))}return b}};c=c||[];var e={};b.cookie.split(";").map(function(a){return a=a.trim().split("="),[a[0],a.slice(1).join("=")]}).forEach(function(a){e[a[0]]=a[1]});var f={};(a.location.search||"?").substring(1).split("&").map(function(a){return a=a.trim().split("="),[a[0],a.slice(1).join("=")]}).forEach(function(a){f[a[0]]=decodeURIComponent(a[1])});var g=!1,h=!0,i=null,j={newUser:!0,uid:null,brandId:null,enableRedirect:!0},k=/^https?:/i,l={ALLOW_BROWSERS:["CHROME","SAFARI"],EV_COOKIE:"__evv",EV_ID_COOKIE:"__evuid",EV_ID_URL_PARAM:"_evid",EV_CONFIRM:"__ev",EV_UID:"__evi",EV_URL:"https://fpc.eyeviewads.com",TRACKER:"https://track.eyeviewads.com",REDIRECT_PATH:"/r/",STICKY_PATH:"/sticky.gif",TPS_PATH:"/3ps.gif",URL_SIZE_LIMIT:2e3};l.normalizeUrl=function(b){var c=b.match(/^([-A-Za-z0-9+.]+:)?(\/\/)?.+/);if(!c[1]&&c[2])return a.location.protocol+b;if(!c[1]){if("/"===b[0])return a.location.protocol+"//"+a.location.host+b;if("#"===b[0])return a.location.href.replace(/#.*$/,"")+b;if(c=a.location.href.match(/^([-A-Za-z0-9+.]+:)?\/\/(.+?)(?:\/(.*?))?(\?.*?)?(#.*)?$/),c[3]=c[3]||"","?"===b[0])c[3]+=b;else if(c[3]&&/\.[-A-Za-z0-9_]+$/.test(c[3])){var d=c[3].split("/");d.splice(-1,1,b),c[3]=d.join("/")}else c[3]+=(c[3]&&"/"!==c[3][c[3].length-1]?"/":"")+b;return(c[1]||a.location.protocol)+"//"+c[2]+"/"+(c[3]||"")}return b},l.browser=function(){var a=navigator.userAgent,b=a.match(/(opera|chrome|safari|firefox|msie|trident(?=\/))\/?\s*(\d+)/i)||[];if(/trident/i.test(b[1]))return"MSIE";if("Chrome"===b[1]){var c=a.match(/\b(OPR|Edge)\/(\d+)/);if(null!==c)return c[1].replace("OPR","Opera").toUpperCase()}return(b[1]||"Unknown").toUpperCase()}();var m=Date.now||function(){return(new Date).getTime()},n=function(b){return-1!==b.indexOf("://"+a.location.host)},o=function(a){if(j.enableRedirect&&j.newUser&&!h){for(var c,e=a.target;e;){if("A"===(e.tagName||"").toUpperCase()&&e.href){c=e;break}if(!e.parentElement||e.parentElement===a.currentTarget)break;e=e.parentElement}if(c){b.cookie=l.EV_COOKIE+"=1; Path=/; "+("MSIE"!==l.browser?"Expires=0; ":"");var f=l.normalizeUrl(c.href);if(k.test(f)){var g=l.EV_URL+l.REDIRECT_PATH+d.encode(f).replace(/=/g,""),i={};j.uid&&(i.u=j.uid,i.n=j.newUser?"1":null),n(f)&&(i.i="1"),i.bid=j.brandId,g=q(g,i),g.length<=l.URL_SIZE_LIMIT&&(c.href=g)}}}},p=function(a){if(a){var b=[];for(var c in a)a.hasOwnProperty(c)&&a[c]&&b.push(c+"="+encodeURIComponent(a[c]));return b.join("&")}return""},q=function(a,b){if(b){var c=p(b);c&&(a+=(-1!==a.indexOf("?")?"&":"?")+c)}return a},r=function(a,b){try{var c=new Image;c.onload=function(){"function"==typeof b&&b.apply(this,[!0])},c.onerror=function(){"function"==typeof b&&b.apply(this,[!1])},i&&i.appendChild(c),c.src=a}catch(d){"function"==typeof b&&b(!1)}},s=function(c,d){var e=l.TRACKER+"/vst/"+j.brandId+"/"+c+".gif",f="pix_src=JS";j.uid&&(f+="&"+l.EV_ID_URL_PARAM+"="+encodeURIComponent(j.uid||"")),d&&"object"==typeof d||(d={}),d.pix_src=null,d.ts=m(),a&&("object"==typeof a.location&&(d.url||(d.url=a.location.pathname+(a.location.search||"")),d.domain||(d.domain=a.location.host)),b&&!d.page&&(d.page=b.title));var g=p(d);return g&&(f+="&"+g),e+"?"+f},t=function(){var a=q(l.EV_URL+l.STICKY_PATH,{u:j.uid,bid:j.brandId});r(a)},u=function(a){var b=q(l.EV_URL+l.TPS_PATH,{u:j.uid,bid:j.brandId});r(b,function(b){b&&(j.newUser=!1),h=b,"function"==typeof a&&a()})};l.push=function(a){if(!g)return void c.push(a);if(a&&"object"==typeof a&&a.length>0)r(s(a[0],a[1]));else if("string"==typeof a)if(":"===a[0]){var b=a.split(":");switch(b[1]){case"uuid":j.uid=b[2],j.newUser=!1}}else r(s(a))};var v=function(){for(;c.length>0;)l.push(c.pop())},w=function(){try{var a=b.getElementsByTagName("body")[0],c=b.createElement("div");c.style.display="none",c.id="ev-pixel-target",a.appendChild(c),i=c}catch(d){}setTimeout(function(){"2"===f[l.EV_CONFIRM]&&t(),j.newUser?u(function(){g=!0,v()}):(g=!0,v())},0),-1!==l.ALLOW_BROWSERS.indexOf(l.browser)&&b.addEventListener("click",function(){try{o.apply(this,arguments)}catch(d){}})};return l.init=function(c){g||(c=c||{},j.brandId=c.b||null,c.e?(j.uid=c.u||e[l.EV_ID_COOKIE],j.newUser=!1):(j.uid=f[l.EV_UID]||e[l.EV_ID_COOKIE]||c.u,f[l.EV_UID]||e[l.EV_COOKIE]?j.newUser=!1:j.newUser=!c.e),void 0!==c.er&&(j.enableRedirect=!!c.er),j.uid&&(b.cookie=l.EV_ID_COOKIE+"="+j.uid+"; Path=/; "+("MSIE"!==l.browser?"Expires=0; ":"")),"complete"===b.readyState?w():a.addEventListener("load",w))},l}(window,document,window._EV);

_EV.init({"u":"845515fd77cbeda0c1dd4fa373fea639:1365:2ab40500cbbc48f6c79a2326b5962b19", "e":true, "b":"bf266a79", "er":false});
