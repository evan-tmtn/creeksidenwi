/*
 A JavaScript implementation of the SHA family of hashes, as
 defined in FIPS PUB 180-4 and FIPS PUB 202, as well as the corresponding
 HMAC implementation as defined in FIPS PUB 198a

 Copyright Brian Turek 2008-2016
 Distributed under the BSD License
 See http://caligatio.github.com/jsSHA/ for more information

 Several functions taken from Paul Johnston
 */
(function(G){'use strict';function t(e,a,d){var g=0,c=[],b=0,f,k,l,h,m,w,n,y,p=!1,q=[],t=[],v,u=!1;d=d||{};f=d.encoding||"UTF8";v=d.numRounds||1;l=z(a,f);if(v!==parseInt(v,10)||1>v)throw Error("numRounds must a integer >= 1");if("SHA-1"===e)m=512,w=A,n=H,h=160,y=function(a){return a.slice()};else throw Error("Chosen SHA variant is not supported");k=x(e);this.setHMACKey=function(a,b,c){var d;if(!0===p)throw Error("HMAC key already set");if(!0===u)throw Error("Cannot set HMAC key after calling update");
    f=(c||{}).encoding||"UTF8";b=z(b,f)(a);a=b.binLen;b=b.value;d=m>>>3;c=d/4-1;if(d<a/8){for(b=n(b,a,0,x(e),h);b.length<=c;)b.push(0);b[c]&=4294967040}else if(d>a/8){for(;b.length<=c;)b.push(0);b[c]&=4294967040}for(a=0;a<=c;a+=1)q[a]=b[a]^909522486,t[a]=b[a]^1549556828;k=w(q,k);g=m;p=!0};this.update=function(a){var d,e,f,h=0,n=m>>>5;d=l(a,c,b);a=d.binLen;e=d.value;d=a>>>5;for(f=0;f<d;f+=n)h+m<=a&&(k=w(e.slice(f,f+n),k),h+=m);g+=h;c=e.slice(h>>>5);b=a%m;u=!0};this.getHash=function(a,d){var f,l,m,r;if(!0===
    p)throw Error("Cannot call getHash after setting HMAC key");m=B(d);switch(a){case "HEX":f=function(a){return C(a,h,m)};break;case "B64":f=function(a){return D(a,h,m)};break;case "BYTES":f=function(a){return E(a,h)};break;case "ARRAYBUFFER":try{l=new ArrayBuffer(0)}catch(I){throw Error("ARRAYBUFFER not supported by this environment");}f=function(a){return F(a,h)};break;default:throw Error("format must be HEX, B64, BYTES, or ARRAYBUFFER");}r=n(c.slice(),b,g,y(k),h);for(l=1;l<v;l+=1)r=n(r,h,0,x(e),h);
    return f(r)};this.getHMAC=function(a,d){var f,l,q,r;if(!1===p)throw Error("Cannot call getHMAC without first setting HMAC key");q=B(d);switch(a){case "HEX":f=function(a){return C(a,h,q)};break;case "B64":f=function(a){return D(a,h,q)};break;case "BYTES":f=function(a){return E(a,h)};break;case "ARRAYBUFFER":try{f=new ArrayBuffer(0)}catch(I){throw Error("ARRAYBUFFER not supported by this environment");}f=function(a){return F(a,h)};break;default:throw Error("outputFormat must be HEX, B64, BYTES, or ARRAYBUFFER");
}l=n(c.slice(),b,g,y(k),h);r=w(t,x(e));r=n(l,h,m,r,h);return f(r)}}function J(e,a,d){var g=e.length,c,b,f,k,l;a=a||[0];d=d||0;l=d>>>3;if(0!==g%2)throw Error("String of HEX type must be in byte increments");for(c=0;c<g;c+=2){b=parseInt(e.substr(c,2),16);if(isNaN(b))throw Error("String of HEX type contains invalid characters");k=(c>>>1)+l;for(f=k>>>2;a.length<=f;)a.push(0);a[f]|=b<<8*(3-k%4)}return{value:a,binLen:4*g+d}}function K(e,a,d){var g=[],c,b,f,k,g=a||[0];d=d||0;b=d>>>3;for(c=0;c<e.length;c+=
    1)a=e.charCodeAt(c),k=c+b,f=k>>>2,g.length<=f&&g.push(0),g[f]|=a<<8*(3-k%4);return{value:g,binLen:8*e.length+d}}function L(e,a,d){var g=[],c=0,b,f,k,l,h,m,g=a||[0];d=d||0;a=d>>>3;if(-1===e.search(/^[a-zA-Z0-9=+\/]+$/))throw Error("Invalid character in base-64 string");f=e.indexOf("=");e=e.replace(/\=/g,"");if(-1!==f&&f<e.length)throw Error("Invalid '=' found in base-64 string");for(f=0;f<e.length;f+=4){h=e.substr(f,4);for(k=l=0;k<h.length;k+=1)b="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".indexOf(h[k]),
    l|=b<<18-6*k;for(k=0;k<h.length-1;k+=1){m=c+a;for(b=m>>>2;g.length<=b;)g.push(0);g[b]|=(l>>>16-8*k&255)<<8*(3-m%4);c+=1}}return{value:g,binLen:8*c+d}}function M(e,a,d){var g=[],c,b,f,g=a||[0];d=d||0;c=d>>>3;for(a=0;a<e.byteLength;a+=1)f=a+c,b=f>>>2,g.length<=b&&g.push(0),g[b]|=e[a]<<8*(3-f%4);return{value:g,binLen:8*e.byteLength+d}}function C(e,a,d){var g="";a/=8;var c,b;for(c=0;c<a;c+=1)b=e[c>>>2]>>>8*(3-c%4),g+="0123456789abcdef".charAt(b>>>4&15)+"0123456789abcdef".charAt(b&15);return d.outputUpper?
    g.toUpperCase():g}function D(e,a,d){var g="",c=a/8,b,f,k;for(b=0;b<c;b+=3)for(f=b+1<c?e[b+1>>>2]:0,k=b+2<c?e[b+2>>>2]:0,k=(e[b>>>2]>>>8*(3-b%4)&255)<<16|(f>>>8*(3-(b+1)%4)&255)<<8|k>>>8*(3-(b+2)%4)&255,f=0;4>f;f+=1)8*b+6*f<=a?g+="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".charAt(k>>>6*(3-f)&63):g+=d.b64Pad;return g}function E(e,a){var d="",g=a/8,c,b;for(c=0;c<g;c+=1)b=e[c>>>2]>>>8*(3-c%4)&255,d+=String.fromCharCode(b);return d}function F(e,a){var d=a/8,g,c=new ArrayBuffer(d);
    for(g=0;g<d;g+=1)c[g]=e[g>>>2]>>>8*(3-g%4)&255;return c}function B(e){var a={outputUpper:!1,b64Pad:"=",shakeLen:-1};e=e||{};a.outputUpper=e.outputUpper||!1;!0===e.hasOwnProperty("b64Pad")&&(a.b64Pad=e.b64Pad);if("boolean"!==typeof a.outputUpper)throw Error("Invalid outputUpper formatting option");if("string"!==typeof a.b64Pad)throw Error("Invalid b64Pad formatting option");return a}function z(e,a){var d;switch(a){case "UTF8":case "UTF16BE":case "UTF16LE":break;default:throw Error("encoding must be UTF8, UTF16BE, or UTF16LE");
}switch(e){case "HEX":d=J;break;case "TEXT":d=function(d,c,b){var f=[],e=[],l=0,h,m,q,n,p,f=c||[0];c=b||0;q=c>>>3;if("UTF8"===a)for(h=0;h<d.length;h+=1)for(b=d.charCodeAt(h),e=[],128>b?e.push(b):2048>b?(e.push(192|b>>>6),e.push(128|b&63)):55296>b||57344<=b?e.push(224|b>>>12,128|b>>>6&63,128|b&63):(h+=1,b=65536+((b&1023)<<10|d.charCodeAt(h)&1023),e.push(240|b>>>18,128|b>>>12&63,128|b>>>6&63,128|b&63)),m=0;m<e.length;m+=1){p=l+q;for(n=p>>>2;f.length<=n;)f.push(0);f[n]|=e[m]<<8*(3-p%4);l+=1}else if("UTF16BE"===
    a||"UTF16LE"===a)for(h=0;h<d.length;h+=1){b=d.charCodeAt(h);"UTF16LE"===a&&(m=b&255,b=m<<8|b>>>8);p=l+q;for(n=p>>>2;f.length<=n;)f.push(0);f[n]|=b<<8*(2-p%4);l+=2}return{value:f,binLen:8*l+c}};break;case "B64":d=L;break;case "BYTES":d=K;break;case "ARRAYBUFFER":try{d=new ArrayBuffer(0)}catch(g){throw Error("ARRAYBUFFER not supported by this environment");}d=M;break;default:throw Error("format must be HEX, TEXT, B64, BYTES, or ARRAYBUFFER");}return d}function p(e,a){return e<<a|e>>>32-a}function q(e,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          a){var d=(e&65535)+(a&65535);return((e>>>16)+(a>>>16)+(d>>>16)&65535)<<16|d&65535}function u(e,a,d,g,c){var b=(e&65535)+(a&65535)+(d&65535)+(g&65535)+(c&65535);return((e>>>16)+(a>>>16)+(d>>>16)+(g>>>16)+(c>>>16)+(b>>>16)&65535)<<16|b&65535}function x(e){var a=[];if("SHA-1"===e)a=[1732584193,4023233417,2562383102,271733878,3285377520];else throw Error("No SHA variants supported");return a}function A(e,a){var d=[],g,c,b,f,k,l,h;g=a[0];c=a[1];b=a[2];f=a[3];k=a[4];for(h=0;80>h;h+=1)d[h]=16>h?e[h]:p(d[h-
    3]^d[h-8]^d[h-14]^d[h-16],1),l=20>h?u(p(g,5),c&b^~c&f,k,1518500249,d[h]):40>h?u(p(g,5),c^b^f,k,1859775393,d[h]):60>h?u(p(g,5),c&b^c&f^b&f,k,2400959708,d[h]):u(p(g,5),c^b^f,k,3395469782,d[h]),k=f,f=b,b=p(c,30),c=g,g=l;a[0]=q(g,a[0]);a[1]=q(c,a[1]);a[2]=q(b,a[2]);a[3]=q(f,a[3]);a[4]=q(k,a[4]);return a}function H(e,a,d,g){var c;for(c=(a+65>>>9<<4)+15;e.length<=c;)e.push(0);e[a>>>5]|=128<<24-a%32;a+=d;e[c]=a&4294967295;e[c-1]=a/4294967296|0;a=e.length;for(c=0;c<a;c+=16)g=A(e.slice(c,c+16),g);return g}
    "function"===typeof define&&define.amd?define(function(){return t}):"undefined"!==typeof exports?("undefined"!==typeof module&&module.exports&&(module.exports=t),exports=t):G.jsSHA=t})(this);
var adTagProtocol = ("https:" === window.location.protocol)? "https:" : "http:";
(function(i) {
    var f = document,
        e = f.createElement("script"),
        h = f.getElementsByTagName("script")[0];
    e.type = "text/javascript";
    e.src = adTagProtocol + "//www.googletagservices.com/tag/js/gpt.js";
    h.parentNode.insertBefore(e, h)
})();
! function() {
    function aq() {}

    function ak(a) {
        return a
    }

    function aA(a) {
        return !!a
    }

    function am(a) {
        return !a
    }

    function aj(a) {
        return function() {
            if (null === a) {
                throw new Error("Callback was already called.")
            }
            a.apply(this, arguments), a = null
        }
    }

    function aw(a) {
        return function() {
            null !== a && (a.apply(this, arguments), a = null)
        }
    }

    function ap(a) {
        return R(a) || "number" == typeof a.length && a.length >= 0 && a.length % 1 === 0
    }

    function aC(d, a) {
        for (var c = -1, b = d.length; ++c < b;) {
            a(d[c], c, d)
        }
    }

    function aE(f, b) {
        for (var d = -1, c = f.length, a = Array(c); ++d < c;) {
            a[d] = b(f[d], d, f)
        }
        return a
    }

    function az(a) {
        return aE(Array(a), function(c, b) {
            return b
        })
    }

    function at(c, a, b) {
        return aC(c, function(f, e, d) {
            b = a(b, f, e, d)
        }), b
    }

    function al(b, a) {
        aC(F(b), function(c) {
            a(b[c], c)
        })
    }

    function ao(c, a) {
        for (var b = 0; b < c.length; b++) {
            if (c[b] === a) {
                return b
            }
        }
        return -1
    }

    function ax(d) {
        var a, c, b = -1;
        return ap(d) ? (a = d.length, function() {
            return b++, a > b ? b : null
        }) : (c = F(d), a = c.length, function() {
            return b++, a > b ? c[b] : null
        })
    }

    function ar(b, a) {
        return a = null == a ? b.length - 1 : +a,
            function() {
                for (var f = Math.max(arguments.length - a, 0), d = Array(f), c = 0; f > c; c++) {
                    d[c] = arguments[c + a]
                }
                switch (a) {
                    case 0:
                        return b.call(this, d);
                    case 1:
                        return b.call(this, arguments[0], d)
                }
            }
    }

    function af(a) {
        return function(b, d, c) {
            return a(b, c)
        }
    }

    function ai(a) {
        return function(j, h, k) {
            k = aw(k || aq), j = j || [];
            var m = ax(j);
            if (0 >= a) {
                return k(null)
            }
            var d = !1,
                i = 0,
                b = !1;
            ! function g() {
                if (d && 0 >= i) {
                    return k(null)
                }
                for (; a > i && !b;) {
                    var c = m();
                    if (null === c) {
                        return d = !0, void(0 >= i && k(null))
                    }
                    i += 1, h(j[c], c, aj(function(e) {
                        i -= 1, e ? (k(e), b = !0) : g()
                    }))
                }
            }()
        }
    }

    function aB(a) {
        return function(b, d, c) {
            return a(N.eachOf, b, d, c)
        }
    }

    function ay(a) {
        return function(c, f, d, b) {
            return a(ai(f), c, d, b)
        }
    }

    function au(a) {
        return function(b, d, c) {
            return a(N.eachOfSeries, b, d, c)
        }
    }

    function aD(b, f, d, a) {
        a = aw(a || aq), f = f || [];
        var g = ap(f) ? [] : {};
        b(f, function(i, c, h) {
            d(i, function(j, e) {
                g[c] = e, h(j)
            })
        }, function(c) {
            a(c, g)
        })
    }

    function ah(f, b, d, c) {
        var a = [];
        f(b, function(h, e, g) {
            d(h, function(i) {
                i && a.push({
                    index: e,
                    value: h
                }), g()
            })
        }, function() {
            c(aE(a.sort(function(g, e) {
                return g.index - e.index
            }), function(e) {
                return e.value
            }))
        })
    }

    function Q(d, a, c, b) {
        ah(d, a, function(f, e) {
            c(f, function(g) {
                e(!g)
            })
        }, b)
    }

    function K(c, a, b) {
        return function(g, e, f, h) {
            function j() {
                h && h(b(!1, void 0))
            }

            function d(l, k, i) {
                return h ? void f(l, function(m) {
                    h && a(m) && (h(b(!0, l)), h = f = !1), i()
                }) : i()
            }
            arguments.length > 3 ? c(g, e, d, j) : (h = f, f = e, c(g, d, j))
        }
    }

    function Z(b, a) {
        return a
    }

    function V(b, d, c) {
        c = c || aq;
        var a = ap(d) ? [] : {};
        b(d, function(h, f, g) {
            h(ar(function(i, e) {
                e.length <= 1 && (e = e[0]), a[f] = e, g(i)
            }))
        }, function(e) {
            c(e, a)
        })
    }

    function av(f, b, d, c) {
        var a = [];
        f(b, function(h, e, g) {
            d(h, function(j, i) {
                a = a.concat(i || []), g(j)
            })
        }, function(e) {
            c(e, a)
        })
    }

    function X(c, j, g) {
        function b(i, m, l, f) {
            if (null != f && "function" != typeof f) {
                throw new Error("task callback must be a function")
            }
            return i.started = !0, R(m) || (m = [m]), 0 === m.length && i.idle() ? N.setImmediate(function() {
                i.drain()
            }) : (aC(m, function(o) {
                var n = {
                    data: o,
                    callback: f || aq
                };
                l ? i.tasks.unshift(n) : i.tasks.push(n), i.tasks.length === i.concurrency && i.saturated()
            }), void N.setImmediate(i.process))
        }

        function k(f, e) {
            return function() {
                h -= 1;
                var l = !1,
                    i = arguments;
                aC(e, function(m) {
                    aC(a, function(n, o) {
                        n !== m || l || (a.splice(o, 1), l = !0)
                    }), m.callback.apply(m, i)
                }), f.tasks.length + h === 0 && f.drain(), f.process()
            }
        }
        if (null == j) {
            j = 1
        } else {
            if (0 === j) {
                throw new Error("Concurrency must not be zero")
            }
        }
        var h = 0,
            a = [],
            d = {
                tasks: [],
                concurrency: j,
                payload: g,
                saturated: aq,
                empty: aq,
                drain: aq,
                started: !1,
                paused: !1,
                push: function(f, e) {
                    b(d, f, !1, e)
                },
                kill: function() {
                    d.drain = aq, d.tasks = []
                },
                unshift: function(f, e) {
                    b(d, f, !0, e)
                },
                process: function() {
                    for (; !d.paused && h < d.concurrency && d.tasks.length;) {
                        var l = d.payload ? d.tasks.splice(0, d.payload) : d.tasks.splice(0, d.tasks.length),
                            i = aE(l, function(e) {
                                return e.data
                            });
                        0 === d.tasks.length && d.empty(), h += 1, a.push(l[0]);
                        var f = aj(k(d, l));
                        c(i, f)
                    }
                },
                length: function() {
                    return d.tasks.length
                },
                running: function() {
                    return h
                },
                workersList: function() {
                    return a
                },
                idle: function() {
                    return d.tasks.length + h === 0
                },
                pause: function() {
                    d.paused = !0
                },
                resume: function() {
                    if (d.paused !== !1) {
                        d.paused = !1;
                        for (var f = Math.min(d.concurrency, d.tasks.length), e = 1; f >= e; e++) {
                            N.setImmediate(d.process)
                        }
                    }
                }
            };
        return d
    }

    function ag(a) {
        return ar(function(b, c) {
            b.apply(null, c.concat([ar(function(d, f) {
                "object" == typeof console && (d ? console.error && console.error(d) : console[a] && aC(f, function(e) {
                        console[a](e)
                    }))
            })]))
        })
    }

    function ad(a) {
        return function(b, d, c) {
            a(az(b), d, c)
        }
    }

    function J(a) {
        return ar(function(b, d) {
            var c = ar(function(h) {
                var g = this,
                    f = h.pop();
                return a(b, function(j, i, e) {
                    j.apply(g, h.concat([e]))
                }, f)
            });
            return d.length ? c.apply(this, d) : c
        })
    }

    function ae(a) {
        return ar(function(b) {
            var d = b.pop();
            b.push(function() {
                var e = arguments;
                c ? N.setImmediate(function() {
                    d.apply(null, e)
                }) : d.apply(null, e)
            });
            var c = !0;
            a.apply(this, b), c = !1
        })
    }
    var an, N = {},
        ab = "object" == typeof self && self.self === self && self || "object" == typeof global && global.global === global && global || this;
    null != ab && (an = ab.async), N.noConflict = function() {
        return ab.async = an, N
    };
    var Y = Object.prototype.toString,
        R = Array.isArray || function(a) {
                return "[object Array]" === Y.call(a)
            },
        G = function(b) {
            var a = typeof b;
            return "function" === a || "object" === a && !!b
        },
        F = Object.keys || function(c) {
                var a = [];
                for (var b in c) {
                    c.hasOwnProperty(b) && a.push(b)
                }
                return a
            },
        ac = "function" == typeof setImmediate && setImmediate,
        aa = ac ? function(a) {
            ac(a)
        } : function(a) {
            setTimeout(a, 0)
        };
    "object" == typeof process && "function" == typeof process.nextTick ? N.nextTick = process.nextTick : N.nextTick = aa, N.setImmediate = ac ? aa : N.nextTick, N.forEach = N.each = function(c, a, b) {
        return N.eachOf(c, af(a), b)
    }, N.forEachSeries = N.eachSeries = function(c, a, b) {
        return N.eachOfSeries(c, af(a), b)
    }, N.forEachLimit = N.eachLimit = function(d, a, c, b) {
        return ai(a)(d, af(c), b)
    }, N.forEachOf = N.eachOf = function(d, i, g) {
        function j(a) {
            h--, a ? g(a) : null === k && 0 >= h && g(null)
        }
        g = aw(g || aq), d = d || [];
        for (var k, b = ax(d), h = 0; null != (k = b());) {
            h += 1, i(d[k], k, aj(j))
        }
        0 === h && g(null)
    }, N.forEachOfSeries = N.eachOfSeries = function(d, g, f) {
        function h() {
            var a = !0;
            return null === b ? f(null) : (g(d[b], b, aj(function(c) {
                if (c) {
                    f(c)
                } else {
                    if (b = i(), null === b) {
                        return f(null)
                    }
                    a ? N.setImmediate(h) : h()
                }
            })), void(a = !1))
        }
        f = aw(f || aq), d = d || [];
        var i = ax(d),
            b = i();
        h()
    }, N.forEachOfLimit = N.eachOfLimit = function(d, a, c, b) {
        ai(a)(d, c, b)
    }, N.map = aB(aD), N.mapSeries = au(aD), N.mapLimit = ay(aD), N.inject = N.foldl = N.reduce = function(d, a, c, b) {
        N.eachOfSeries(d, function(g, f, e) {
            c(a, g, function(i, h) {
                a = h, e(i)
            })
        }, function(e) {
            b(e, a)
        })
    }, N.foldr = N.reduceRight = function(f, d, c, a) {
        var b = aE(f, ak).reverse();
        N.reduce(b, d, c, a)
    }, N.transform = function(d, a, c, b) {
        3 === arguments.length && (b = c, c = a, a = R(d) ? [] : {}), N.eachOf(d, function(g, f, e) {
            c(a, g, f, e)
        }, function(e) {
            b(e, a)
        })
    }, N.select = N.filter = aB(ah), N.selectLimit = N.filterLimit = ay(ah), N.selectSeries = N.filterSeries = au(ah), N.reject = aB(Q), N.rejectLimit = ay(Q), N.rejectSeries = au(Q), N.any = N.some = K(N.eachOf, aA, ak), N.someLimit = K(N.eachOfLimit, aA, ak), N.all = N.every = K(N.eachOf, am, am), N.everyLimit = K(N.eachOfLimit, am, am), N.detect = K(N.eachOf, ak, Z), N.detectSeries = K(N.eachOfSeries, ak, Z), N.detectLimit = K(N.eachOfLimit, ak, Z), N.sortBy = function(d, a, c) {
        function b(i, f) {
            var h = i.criteria,
                g = f.criteria;
            return g > h ? -1 : h > g ? 1 : 0
        }
        N.map(d, function(g, f) {
            a(g, function(e, h) {
                e ? f(e) : f(null, {
                    value: g,
                    criteria: h
                })
            })
        }, function(f, e) {
            return f ? c(f) : void c(null, aE(e.sort(b), function(g) {
                return g.value
            }))
        })
    }, N.auto = function(w, l, b) {
        function s(a) {
            j.unshift(a)
        }

        function c(d) {
            var a = ao(j, d);
            a >= 0 && j.splice(a, 1)
        }

        function p() {
            i--, aC(j.slice(0), function(a) {
                a()
            })
        }
        "function" == typeof arguments[1] && (b = l, l = null), b = aw(b || aq);
        var k = F(w),
            i = k.length;
        if (!i) {
            return b(null)
        }
        l || (l = i);
        var n = {},
            q = 0,
            m = !1,
            j = [];
        s(function() {
            i || b(null, n)
        }), aC(k, function(v) {
            function e() {
                return l > q && at(d, function(g, f) {
                        return g && n.hasOwnProperty(f)
                    }, !0) && !n.hasOwnProperty(v)
            }

            function u() {
                e() && (q++, c(u), o[o.length - 1](r, n))
            }
            if (!m) {
                for (var t, o = R(w[v]) ? w[v] : [w[v]], r = ar(function(g, h) {
                    if (q--, h.length <= 1 && (h = h[0]), g) {
                        var f = {};
                        al(n, function(y, x) {
                            f[x] = y
                        }), f[v] = h, m = !0, b(g, f)
                    } else {
                        n[v] = h, N.setImmediate(p)
                    }
                }), d = o.slice(0, o.length - 1), a = d.length; a--;) {
                    if (!(t = w[d[a]])) {
                        throw new Error("Has nonexistent dependency in " + d.join(", "))
                    }
                    if (R(t) && ao(t, v) >= 0) {
                        throw new Error("Has cyclic dependencies")
                    }
                }
                e() ? (q++, o[o.length - 1](r, n)) : s(u)
            }
        })
    }, N.retry = function(g, q, k) {
        function b(c, a) {
            if ("number" == typeof a) {
                c.times = parseInt(a, 10) || h
            } else {
                if ("object" != typeof a) {
                    throw new Error("Unsupported argument type for 'times': " + typeof a)
                }
                c.times = parseInt(a.times, 10) || h, c.interval = parseInt(a.interval, 10) || d
            }
        }

        function p(o, c) {
            function i(s, r) {
                return function(e) {
                    s(function(v, u) {
                        e(!v || r, {
                            err: v,
                            result: u
                        })
                    }, c)
                }
            }

            function f(e) {
                return function(n) {
                    setTimeout(function() {
                        n(null)
                    }, e)
                }
            }
            for (; m.times;) {
                var a = !(m.times -= 1);
                l.push(i(m.task, a)), !a && m.interval > 0 && l.push(f(m.interval))
            }
            N.series(l, function(n, r) {
                r = r[r.length - 1], (o || m.callback)(r.err, r.result)
            })
        }
        var h = 5,
            d = 0,
            l = [],
            m = {
                times: h,
                interval: d
            },
            j = arguments.length;
        if (1 > j || j > 3) {
            throw new Error("Invalid arguments - must be either (task), (task, callback), (times, task) or (times, task, callback)")
        }
        return 2 >= j && "function" == typeof g && (k = q, q = g), "function" != typeof g && b(m, g), m.callback = k, m.task = q, m.callback ? p() : p
    }, N.waterfall = function(b, d) {
        function c(e) {
            return ar(function(h, f) {
                if (h) {
                    d.apply(null, [h].concat(f))
                } else {
                    var g = e.next();
                    g ? f.push(c(g)) : f.push(d), ae(e).apply(null, f)
                }
            })
        }
        if (d = aw(d || aq), !R(b)) {
            var a = new Error("First argument to waterfall must be an array of functions");
            return d(a)
        }
        return b.length ? void c(N.iterator(b))() : d()
    }, N.parallel = function(b, a) {
        V(N.eachOf, b, a)
    }, N.parallelLimit = function(c, a, b) {
        V(ai(a), c, b)
    }, N.series = function(b, a) {
        V(N.eachOfSeries, b, a)
    }, N.iterator = function(b) {
        function a(d) {
            function c() {
                return b.length && b[d].apply(null, arguments), c.next()
            }
            return c.next = function() {
                return d < b.length - 1 ? a(d + 1) : null
            }, c
        }
        return a(0)
    }, N.apply = ar(function(b, a) {
        return ar(function(c) {
            return b.apply(null, a.concat(c))
        })
    }), N.concat = aB(av), N.concatSeries = au(av), N.whilst = function(b, d, c) {
        if (c = c || aq, b()) {
            var a = ar(function(f, e) {
                f ? c(f) : b.apply(this, e) ? d(a) : c.apply(null, [null].concat(e))
            });
            d(a)
        } else {
            c(null)
        }
    }, N.doWhilst = function(d, a, c) {
        var b = 0;
        return N.whilst(function() {
            return ++b <= 1 || a.apply(this, arguments)
        }, d, c)
    }, N.until = function(c, a, b) {
        return N.whilst(function() {
            return !c.apply(this, arguments)
        }, a, b)
    }, N.doUntil = function(c, a, b) {
        return N.doWhilst(c, function() {
            return !a.apply(this, arguments)
        }, b)
    }, N.during = function(c, f, d) {
        d = d || aq;
        var a = ar(function(h, g) {
                h ? d(h) : (g.push(b), c.apply(this, g))
            }),
            b = function(g, e) {
                g ? d(g) : e ? f(a) : d(null)
            };
        c(b)
    }, N.doDuring = function(d, a, c) {
        var b = 0;
        N.during(function(e) {
            b++ < 1 ? e(null, !0) : a.apply(this, arguments)
        }, d, c)
    }, N.queue = function(c, a) {
        var b = X(function(d, f) {
            c(d[0], f)
        }, a, 1);
        return b
    }, N.priorityQueue = function(c, f) {
        function d(h, e) {
            return h.priority - e.priority
        }

        function a(o, k, m) {
            for (var l = -1, h = o.length - 1; h > l;) {
                var j = l + (h - l + 1 >>> 1);
                m(k, o[j]) >= 0 ? l = j : h = j - 1
            }
            return l
        }

        function b(j, k, h, l) {
            if (null != l && "function" != typeof l) {
                throw new Error("task callback must be a function")
            }
            return j.started = !0, R(k) || (k = [k]), 0 === k.length ? N.setImmediate(function() {
                j.drain()
            }) : void aC(k, function(i) {
                var m = {
                    data: i,
                    priority: h,
                    callback: "function" == typeof l ? l : aq
                };
                j.tasks.splice(a(j.tasks, m, d) + 1, 0, m), j.tasks.length === j.concurrency && j.saturated(), N.setImmediate(j.process)
            })
        }
        var g = N.queue(c, f);
        return g.push = function(j, h, i) {
            b(g, j, h, i)
        }, delete g.unshift, g
    }, N.cargo = function(b, a) {
        return X(b, 1, a)
    }, N.log = ag("log"), N.dir = ag("dir"), N.memoize = function(g, d) {
        var c = {},
            a = {},
            b = Object.prototype.hasOwnProperty;
        d = d || ak;
        var f = ar(function(e) {
            var h = e.pop(),
                i = d.apply(null, e);
            b.call(c, i) ? N.setImmediate(function() {
                h.apply(null, c[i])
            }) : b.call(a, i) ? a[i].push(h) : (a[i] = [h], g.apply(null, e.concat([ar(function(m) {
                c[i] = m;
                var k = a[i];
                delete a[i];
                for (var l = 0, j = k.length; j > l; l++) {
                    k[l].apply(null, m)
                }
            })])))
        });
        return f.memo = c, f.unmemoized = g, f
    }, N.unmemoize = function(a) {
        return function() {
            return (a.unmemoized || a).apply(null, arguments)
        }
    }, N.times = ad(N.map), N.timesSeries = ad(N.mapSeries), N.timesLimit = function(d, a, c, b) {
        return N.mapLimit(az(d), a, c, b)
    }, N.seq = function() {
        var a = arguments;
        return ar(function(d) {
            var c = this,
                b = d[d.length - 1];
            "function" == typeof b ? d.pop() : b = aq, N.reduce(a, d, function(h, f, g) {
                f.apply(c, h.concat([ar(function(i, e) {
                    g(i, e)
                })]))
            }, function(f, e) {
                b.apply(c, [f].concat(e))
            })
        })
    }, N.compose = function() {
        return N.seq.apply(null, Array.prototype.reverse.call(arguments))
    }, N.applyEach = J(N.eachOf), N.applyEachSeries = J(N.eachOfSeries), N.forever = function(b, d) {
        function c(e) {
            return e ? a(e) : void f(c)
        }
        var a = aj(d || aq),
            f = ae(b);
        c()
    }, N.ensureAsync = ae, N.constant = ar(function(b) {
        var a = [null].concat(b);
        return function(c) {
            return c.apply(this, a)
        }
    }), N.wrapSync = N.asyncify = function(a) {
        return ar(function(c) {
            var f, d = c.pop();
            try {
                f = a.apply(this, c)
            } catch (b) {
                return d(b)
            }
            G(f) && "function" == typeof f.then ? f.then(function(e) {
                d(null, e)
            })["catch"](function(e) {
                d(e.message ? e : new Error(e))
            }) : d(null, f)
        })
    }, ab.async = N
}();
async.parallelWithTimeout = function(c, a, f, e) {
    var d = f.map(function(g) {
        return function(h) {
            g.callback(function(j, i) {
                g.isCompleted = true;
                h(j, i)
            })
        }
    });
    var b = setTimeout(function() {
        b = null;
        for (var g = 0; g < f.length; g++) {
            if (!f[g].isCompleted) {
                console.log(c + " timeout occurred - " + f[g].name)
            }
        }
        e("async.parallel timed out out after " + a + "ms.", null)
    }, a);
    async.parallel(d, function(h, g) {
        if (b) {
            clearTimeout(b);
            e(h, g)
        }
    })
};
(function(c) {
    var d = [],
        a = {},
        k = {},
        h = function() {};
    var l = "-----";
    l += l;
    l += l;
    l += l;
    l += l;
    var g = "\n\n\n\n\n\n";
    var j = window.performance,
        b = j && (j.now || j.mozNow || j.msNow || j.oNow || j.webkitNow);

    function e() {
        return (b && b.call(j)) || (new Date().getTime())
    }
    if (!c.log || typeof(c.log) !== "function") {
        c.log = h
    }
    if (!c.profile || typeof(c.profile) !== "function") {
        c.profile = h
    }
    if (!c.profileEnd || typeof(c.profileEnd) !== "function") {
        c.profileEnd = h
    }
    if (!c.timeStamp || typeof(c.timeStamp) !== "function") {
        c.timeStamp = h
    }
    if (!c.trace || typeof(c.trace) !== "function") {
        c.trace = h
    }
    if (!c.debug || typeof(c.debug) !== "function") {
        c.debug = c.log
    }
    if (!c.info || typeof(c.info) !== "function") {
        c.info = c.log
    }
    if (!c.warn || typeof(c.warn) !== "function") {
        c.warn = c.log
    }
    if (!c.error || typeof(c.error) !== "function") {
        c.error = c.log
    }
    if (!c.dir || typeof(c.dir) !== "function") {
        c.dir = c.log
    }
    if (!c.dirxml || typeof(c.dirxml) !== "function") {
        c.dirxml = c.dir
    }
    var i = false;
    if (i || !c.group) {
        c.group = function(f) {
            d.push(f);
            c.log(l + "\nBEGIN GROUP: " + f + "")
        }
    }
    if (i || !c.groupCollapsed) {
        c.groupCollapsed = c.group
    }
    if (i || !c.groupEnd) {
        c.groupEnd = function() {
            c.log("END GROUP: " + d.pop() + "\n" + l)
        }
    }
    if (i || !c.time) {
        c.time = function(f) {
            a[f] = e()
        }
    }
    if (i || !c.timeEnd) {
        c.timeEnd = function(f) {
            c.log(f + ": " + (e() - a[f]).toFixed(3) + "ms");
            delete(a[f])
        }
    }
    if (i || !c.assert) {
        c.assert = function(m, f) {
            if (!m) {
                c.error("Assertion failed: " + f)
            }
        }
    }
    if (i || !c.count) {
        c.count = function(f) {
            if (!k[f]) {
                k[f] = 0
            }
            k[f]++;
            c.log(f + ": " + k[f])
        }
    }
    if (i || !c.clear) {
        c.clear = function() {
            c.log(g)
        }
    }
})(window.console = window.console || {});
!window.addEventListener && (function(b, e, f, d, c, g, a) {
    b[d] = e[d] = f[d] = function(h, i) {
        var j = this;
        a.unshift([j, h, i, function(k) {
            k.currentTarget = j;
            k.preventDefault = function() {
                k.returnValue = false
            };
            k.stopPropagation = function() {
                k.cancelBubble = true
            };
            k.target = k.srcElement || j;
            i.call(j, k)
        }]);
        this.attachEvent("on" + h, a[0][3])
    };
    b[c] = e[c] = f[c] = function(j, k) {
        for (var h = 0, i; i = a[h]; ++h) {
            if (i[0] == this && i[1] == j && i[2] == k) {
                return this.detachEvent("on" + j, a.splice(h, 1)[0][3])
            }
        }
    };
    b[g] = e[g] = f[g] = function(h) {
        return this.fireEvent("on" + h.type, h)
    }
})(window.prototype, document.prototype, Element.prototype, "addEventListener", "removeEventListener", "dispatchEvent", []);
if (typeof CustomEvent === "undefined" || typeof CustomEvent !== "function") {
    (function() {
        function a(c, d) {
            d = d || {
                    bubbles: false,
                    cancelable: false,
                    detail: undefined
                };
            var b;
            if (document.createEvent) {
                b = document.createEvent("CustomEvent");
                b.initCustomEvent(c, d.bubbles, d.cancelable, d.detail)
            } else {
                if (document.createEventObject) {
                    b = document.createEventObject()
                }
            }
            return b
        }
        a.prototype = window.Event.prototype;
        window.CustomEvent = a
    })()
}
if (!Array.prototype.indexOf) {
    Array.prototype.indexOf = function(c, d) {
        var b;
        if (this === null) {
            throw new TypeError('"this" is null or not defined')
        }
        var e = Object(this);
        var a = e.length >>> 0;
        if (a === 0) {
            return -1
        }
        var f = +d || 0;
        if (Math.abs(f) === Infinity) {
            f = 0
        }
        if (f >= a) {
            return -1
        }
        b = Math.max(f >= 0 ? f : a - Math.abs(f), 0);
        while (b < a) {
            if (b in e && e[b] === c) {
                return b
            }
            b++
        }
        return -1
    }
}
if (!Array.isArray) {
    Array.isArray = function(a) {
        return Object.prototype.toString.call(a) === "[object Array]"
    }
}



var NascarAd = (function() {
    var _slice = Array.prototype.slice;
    var _empty = function() {};
    var _globalPageTargets = [];
    var _globalPageAdId;
    var _isDomReady = false;
    var _callbackObjectBuilder = function(name, callback) {
        return {
            name: name,
            callback: callback
        }
    };

    var _ajax = (function() {

        function _Promise() {
            this._callbacks = [];
        }

        _Promise.prototype.then = function(func, context) {
            var p;
            if (this._isdone) {
                p = func.apply(context, this.result);
            } else {
                p = new _Promise();
                this._callbacks.push(function () {
                    var res = func.apply(context, arguments);
                    if (res && typeof res.then === 'function')
                        res.then(p.done, p);
                });
            }
            return p;
        };

        _Promise.prototype.done = function() {
            this.result = arguments;
            this._isdone = true;
            for (var i = 0; i < this._callbacks.length; i++) {
                this._callbacks[i].apply(null, arguments);
            }
            this._callbacks = [];
        };

        function _encode(data) {
            var payload = "";
            if (typeof data === "string") {
                payload = data;
            } else {
                var e = encodeURIComponent;
                var params = [];

                for (var k in data) {
                    if (data.hasOwnProperty(k)) {
                        params.push(k + '=' + e(data[k]));
                    }
                }
                payload = params.join('&')
            }
            return payload;
        }

        function _new_xhr() {
            var xhr;
            if (window.XMLHttpRequest) {
                xhr = new XMLHttpRequest();
            } else if (window.ActiveXObject) {
                try {
                    xhr = new ActiveXObject("Msxml2.XMLHTTP");
                } catch (e) {
                    xhr = new ActiveXObject("Microsoft.XMLHTTP");
                }
            }
            return xhr;
        }

        var cache = (function(){
            var _requestsCache = {};

            var _generateCacheKey = function(request){
                var key = '';
                key += request.url;
                key += _encode (request.data || {});
                key += (request.method || 'GET');
                key += (request.withCredentials || false);
                return key;
            };

            var _put = function(request, err, data, xhr){
                var key = _generateCacheKey(request);
                var value = [err, data, xhr];
                _requestsCache[key] = value;
                _logDebug("Request cached:" + key, value )
            };

            var _get = function(request){
                var key = _generateCacheKey(request);
                var response = _requestsCache[key];
                _logDebug("Respond from cache for request:" + key, response );
                return response;
            };

            return {
                get: _get,
                put: _put
            }
        })();

        var ajax = function(request) {
            var p = new _Promise();

            var response = cache.get(request);
            if (response){
                _Promise.prototype.done.apply(p, response);
            }

            var xhr, payload,
                url = request.url,
                data = request.data || {},
                headers = request.headers || {},
                method = request.method || 'GET',
                withCredentials = request.withCredentials || false,
                ajaxTimeout = request.ajaxTimeout || ajax.ajaxTimeout;

            try {
                xhr = _new_xhr();
            } catch (e) {
                p.done(ajax.ENOXHR, "", null);
                return p;
            }

            if(withCredentials) {
                if (xhr.withCredentials !== undefined) {
                    xhr.withCredentials = withCredentials;
                } else {
                    p.done(ajax.ENOCORS, "", xhr);
                    return p;
                }
            }

            payload = _encode(data);
            if (method === 'GET' && payload) {
                url += '?' + payload;
                payload = null;
            }

            xhr.open(method, url);

            var content_type = 'application/x-www-form-urlencoded';
            for (var h in headers) {
                if (headers.hasOwnProperty(h)) {
                    if (h.toLowerCase() === 'content-type')
                        content_type = headers[h];
                    else
                        xhr.setRequestHeader(h, headers[h]);
                }
            }
            xhr.setRequestHeader('Content-type', content_type);


            function onTimeout() {
                xhr.abort();
                p.done(ajax.ETIMEOUT, "", xhr);
            }

            var timeout = ajaxTimeout;
            if (timeout) {
                var tid = setTimeout(onTimeout, timeout);
            }

            xhr.onreadystatechange = function() {
                if (timeout) {
                    clearTimeout(tid);
                }
                if (xhr.readyState === 4) {
                    var err = (!xhr.status ||(xhr.status < 200 || xhr.status >= 300) && xhr.status !== 304 ),
                        data = xhr.responseText;

                    if(typeof xhr.getResponseHeader === 'function'){
                        var responseContentType = xhr.getResponseHeader('content-type');
                        if (responseContentType.indexOf('json') > 0){
                            data = JSON.parse(data);
                        }
                    }

                    cache.put(request,err, data, xhr);
                    p.done(err, data, xhr);
                }
            };

            xhr.send(payload);
            return p;
        };
        ajax.ENOXHR= 1;
        ajax.ETIMEOUT= 2;
        ajax.ENOCORS= 3;
        ajax.ajaxTimeout= 0;

        return ajax;
    })();

    function _hendleAjaxError(error,xhr){
        var msg = 'AJAX error. ';
        if(typeof error === 'number'){
            switch (error) {
                case _ajax.ETIMEOUT:
                    msg += "Timeout error."; break;
                case _ajax.ENOXHR:
                    msg += "ALAX is not supported by browser."; break;
                case _ajax.ENOCORS:
                    msg += "CORS is not supported by browser."; break;
                default :
                    msg += "HTTP error, status" + xhr.status; break;
            }
            _logError(msg, xhr);
        }
        _logError("AJAX error: cannot load slots data");
    }

    var Registry = function() {
        var array = [];
        array.push = function(slotsOptions) {
            var copyOfSlotsOptions = _clone(slotsOptions);
            var preQueueCallbacks = _modules.filter(function(module) {
                return !!module.callbacks.preQueueCallback
            }).map(function(module) {
                return _callbackObjectBuilder(module.name, function(data) {
                    module.callbacks.preQueueCallback(copyOfSlotsOptions, data)
                })
            });
            async.parallelWithTimeout("preQueue", _options.queueCallbackTimeoutInMilliseconds, preQueueCallbacks, function(msg) {
                if (msg) {
                    _logWarn("error calling preQueueCallbacks for registered modules", msg)
                }
                Array.prototype.push.call(array, slotsOptions);
                if (!slotsOptions[0].singleton) {
                    _globalPageTargets = slotsOptions[0].targeting;
                    if(slotsOptions[1]){
                        _globalPageAdId = slotsOptions[1].adunit_id
                    }
                }
                var root = slotsOptions[0].root.toUpperCase();
                var id = slotsOptions[0].adunit_name;
                var now = new Date();

                _updateTargets(root, id);
                for (var i = 1; i < slotsOptions.length; i++) {
                    var slotOption = slotsOptions[i];
                    slotOption.parentRegistry = id;
                    slotOption.nascarad_queued_date = now;
                    if (!slotOption.queued) {
                        slotOption.queued = true;
                        _slotQueue.push(slotOption)
                    }
                }
                var copyOfSlotQueue = _clone(_slotQueue);
                var postQueueCallbacks = _modules.filter(function(module) {
                    return !!module.callbacks.postQueueCallback
                }).map(function(module) {
                    return _callbackObjectBuilder(module.name, function(data) {
                        module.callbacks.postQueueCallback(copyOfSlotQueue, data)
                    })
                });
                async.parallelWithTimeout("postQueue", _options.queueCallbackTimeoutInMilliseconds, postQueueCallbacks, function(msg) {
                    if (msg) {
                        _logWarn("error calling postQueueCallbacks for registered modules", msg)
                    }
                    if (_options.autoDispatch) {
                        NascarAd.dispatchQueue()
                    }
                })
            })
        };
        return array
    };

    function _isFunction(obj) {
        return typeof obj === "function"
    }

    function _bind(callback, scope) {
        if (!_isFunction(callback)) {
            throw new TypeError("Bind must be called on a function")
        }
        var argsCloser = _slice.call(arguments, 2);
        return function() {
            return callback.apply(scope, argsCloser.concat(_slice.call(arguments)))
        }
    }

    function _log() {
        window.console.log.apply(window.console, arguments)
    }

    function addEvent(element, type, callback) {
        if (element.addEventListener) {
            element.addEventListener(type, callback, true)
        } else {
            if (element.attachEvent) {
                element.attachEvent("on" + type, callback)
            }
        }
    }

    function generateSingletonId() {
        return "yyyxxxxyxxxx".replace(/[xy]/g, function(a) {
            var i = Math.random() * 16 | 0,
                hash = a == "x" ? i : (i & 3 | 8);
            return hash.toString(16)
        }).toString()
    }

    function _getParamValue(name) {
        var value = "";
        if (document.location.search) {
            name = name.replace(/[\[]/, "\\[").replace(/[\]]/, "\\]");
            var r = "[\\?&]" + name + "=([^&#]*)";
            var m = new RegExp(r);
            var a = m.exec(document.location.search);
            if (a) {
                value = a[1]
            }
        }
        return value
    }

    function readCookie(name) {
        if (!document.cookie) {
            return null
        } else {
            var cookies = document.cookie.split(";");
            var cookieName = name + "=";
            for (var i = 0; i < cookies.length; i++) {
                var cookie = cookies[i];
                while (cookie.charAt(0) == " ") {
                    cookie = cookie.substring(1, cookie.length)
                }
                if (cookie.indexOf(cookieName) === 0) {
                    return cookie.substring(cookieName.length, cookie.length)
                }
            }
            return null
        }
    }

    function _clone(obj) {
        if (null == obj || "object" != typeof obj) {
            return obj
        }
        if (obj instanceof Date) {
            var date = new Date();
            date.setTime(obj.getTime());
            return date
        }
        if (obj instanceof Array) {
            var arr = [];
            for (var i = 0, az = obj.length; i < az; i++) {
                arr[i] = _clone(obj[i])
            }
            return arr
        }
        if (obj instanceof Object) {
            var object = {};
            for (var key in obj) {
                if (obj.hasOwnProperty(key)) {
                    object[key] = _clone(obj[key])
                }
            }
            return object
        }
        throw new Error("Unable to copy obj! Its type isn't supported.")
    }

    function _merge(o1, o2) {
        var o = {};
        for (var k1 in o1) {
            if (o1.hasOwnProperty(k1)) {
                o[k1] = o1[k1]
            }
        }
        for (var k2 in o2) {
            if (o2.hasOwnProperty(k2)) {
                o[k2] = o2[k2]
            }
        }
        return o
    }
    var _options = {
        maintaincorrelator: false,
        refreshOnFocusOnly: false,
        lazyLoad: false,
        //networkId: "8663477",
        networkId: "73074296",
        autoDispatch: true,
        exclude: [],
        queueCallbackTimeoutInMilliseconds: 300,
        dispatchCallbackTimeoutInMilliseconds: 300,
        refreshCallbackTimeoutInMilliseconds: 300
    };
    var _targets = {
        pageTargets: {},
        slotTargets: {}
    };
    var _isNascarAdInitiated = false;
    var _isFocused = true;
    var _logDebug = (_getParamValue("debug") == "true") ? _bind(_log, null, "[NascarAd - DEBUG]") : _empty;
    var _logWarn = _bind(_log, null, "[NascarAd - WARNING]");
    var _logError = _bind(_log, null, "[NascarAd - ERROR]");
    var pageSlots = {};
    var _slotQueue = [];
    var _testPageTargetKey;
    var _testPageTargetValue;
    var _dispatchQueue = [];
    var _modules = [];
    var _excludes = [];

    var _devices = [
        {key: 'desktop', screenSize:[1025,0]},
        {key: 'tablandscape', screenSize:[769,0]},
        {key: 'tabportrait', screenSize:[700,0]},
        {key: 'mobportrait', screenSize:[300,0]},
        {key: 'moblandscape', screenSize:[480,0]},
        {key: 'defaultsize', screenSize:[0,0]}
    ];

    function _initOnDocumentReadyListeners() {
        var aB = false;

        function __onDOMContentLoaded() {
            if (!aB) {
                aB = true;
                _logDebug("NascarAd DOM Ready Detection");
                _isDomReady = true;
                _dispatchQueueOnceReady()
            }
        }

        function __callback() {
            if (!aB) {
                try {
                    document.documentElement.doScroll("left");
                    __onDOMContentLoaded()
                } catch (error) {
                    setTimeout(__callback, 10)
                }
            }
        }
        if (document.addEventListener) {
            document.addEventListener("DOMContentLoaded", __onDOMContentLoaded, false)
        } else {
            if (document.attachEvent) {
                var flag = false;
                try {
                    flag = window.frameElement !== null
                } catch (error) {}
                if (document.documentElement.doScroll && !flag) {
                    __callback()
                }
                document.attachEvent("onreadystatechange", function() {
                    if (document.readyState === "complete" || document.readyState === "loaded" || document.readyState === "interactive") {
                        __onDOMContentLoaded()
                    }
                })
            }
        }
        if (window.addEventListener) {
            window.addEventListener("load", __onDOMContentLoaded, true)
        } else {
            if (window.attachEvent) {
                window.attachEvent("onload", __onDOMContentLoaded)
            } else {
                var onloadBackup = window.onload;
                window.onload = function() {
                    onloadBackup && onloadBackup();
                    __onDOMContentLoaded()
                }
            }
        }
        var adResizeWindowSize = window.innerWidth;
        var adReszeInterval = null;
        function __onWindowResize() {
            if (adResizeWindowSize != window.innerWidth) {
                clearInterval(adReszeInterval);
                adReszeInterval = setInterval(function() {
                    var adsToRefresh = new Array();

                    for(var k=0; k<adsSlotBreakpointsList.length; k++) {
                        if(adsSlotBreakpointsList[k].breakpoints == '*') {
                            adsToRefresh.push(adsSlotBreakpointsList[k].name);
                        } else {
                            var breakpoints = adsSlotBreakpointsList[k].breakpoints.split(',');
                            for(var n=0; n<breakpoints.length; n++) {
                                var _breakpoint = parseInt(breakpoints[n], 10);
                                if ( (_breakpoint< adResizeWindowSize && _breakpoint >= window.innerWidth) || (_breakpoint > adResizeWindowSize && _breakpoint <= window.innerWidth) ) {
                                    adsToRefresh.push(adsSlotBreakpointsList[k].name);
                                    break;
                                }
                            }
                        }
                    }
                    var adContainers = document.getElementsByClassName('nascar-ad-container');
                    for (var i = 0, len = adContainers.length; i < len; i++) {
                        var adContainer = adContainers[i];
                        var rendered = adContainer.querySelectorAll('.nascar-advertisement.nascarad-rendered');
                        for(var j=0; j<rendered.length; j++) {
                            for(var k=0; k<adsToRefresh.length; k++) {
                                if(rendered[j].id == adsToRefresh[k]) {
                                    adContainer.style.height = adContainer.offsetHeight+'px';
                                }
                            }
                        }
                    }
                    if (adsToRefresh.length) {
                        refreshAds(adsToRefresh);
                    }
                    adResizeWindowSize = window.innerWidth;
                    clearInterval(adReszeInterval);
                }, 1000);
            }
        }
        if (typeof adsSlotBreakpointsList !=='undefined') {
            if (window.addEventListener) {
                window.addEventListener("resize", __onWindowResize, true)
            } else {
                if (window.attachEvent) {
                    window.attachEvent("onresize", __onWindowResize)
                } else {
                    var onresizeBackup = window.onresize;
                    window.resize = function() {
                        onresizeBackup && onresizeBackup();
                        __onWindowResize();
                    }
                }
            }
        }

        if (document.readyState === "complete" || document.readyState === "loaded" || document.readyState === "interactive") {
            __onDOMContentLoaded()
        }
    }

    function _initTestPageTargets() {
        try {
            var param = _getParamValue("test");
            if (param) {
                var arr = param.split("%3D");
                _testPageTargetKey = arr[0];
                _testPageTargetValue = arr[1];
                _targets.pageTargets[_testPageTargetKey] = _testPageTargetValue
            }
        } catch (error) {
            _logError("checkForTest", error)
        }
    }

    function _updateTargets(root, id) {
        // update pageTargets namespace tergets
        if (window[root]) {
            if (window[root].adTargets) {
                for (var key in window[root].adTargets) {
                    if (window[root].adTargets.hasOwnProperty(key)) {
                        _targets.pageTargets[key] = window[root].adTargets[key]
                    }
                }
            }
            if (window[root].slotTargets) {
                for (var key in window[root].slotTargets) {
                    if (window[root].slotTargets.hasOwnProperty(key)) {
                        var values = window[root].slotTargets[key];
                        if (!_targets.slotTargets[key]) {
                            _targets.slotTargets[key] = {}
                        }
                        for (var k in values) {
                            if (values.hasOwnProperty(k)) {
                                _targets.slotTargets[key][k] = values[k]
                            }
                        }
                    }
                }
            }
        }

        // update pageTargets with s1,s2,s3, ... , etc
        var arr = id.split('_'), key;
        if(arr.length > 1){
            for (var i = 1; i<arr.length; i++){
                key = 's' + (i);
                _targets.pageTargets[key] = arr[i];
            }
        }

        // update pageTargets from "test" param.
        if(_testPageTargetKey){
            _targets.pageTargets[_testPageTargetKey] = _testPageTargetValue ? _testPageTargetValue : "";
        }

        // update pageTargets with pid
        _updatePIDPageTargeting();

        //update pageTargets with breakpoint
        _updateBreakpoint();
    }

    function _updatePIDPageTargeting(){
        var shaObj = new jsSHA("SHA-1", "TEXT"),
            pid = window.location.pathname.indexOf('.html') != -1 ? window.location.pathname.substring(0, window.location.pathname.lastIndexOf('.html')) : window.location.pathname;

        shaObj.update(pid);
        _targets.pageTargets['pid'] = shaObj.getHash("HEX");
    }

    function _getPIDPageTargeting(){
        var cName= 'nascarDfpPPIDCookie', temp;
        var value= Date.now() + new Array(26).join().replace(/(.|$)/g, function(){return ((Math.random()*36)|0).toString(36)[Math.random()<.5?"toString":"toUpperCase"]();});
        temp = readCookie(cName);
        console.log(cName);
        if(temp == null || temp == '' || temp.length < 32){
            setDFPCookie(cName, value, 90);// Set PPID cookie for 90 days
            cName= value;
        }else{
            cName= temp
        }
        return cName;
    }

    function _updateBreakpoint(){
        var width = window.innerWidth
                || document.documentElement.clientWidth
                || document.body.clientWidth,
            breakpoint;

        if(width > 769){
            breakpoint = 'desktop';
        } else if(width <=  769 && width >700){
            breakpoint = 'tablet';
        } else{
            breakpoint = 'mobile';
        }
        _targets.pageTargets['breakpoint'] = breakpoint;
    }

    function _getTargets(slotData) {
        var targets = _clone(slotData.targeting);
        if (!Array.isArray(targets)) {
            targets = [targets]
        }
        var oldTargets = _targets.slotTargets;
        if (oldTargets[slotData.slot_id]) {
            for (var key in oldTargets[slotData.slot_id]) {
                if (oldTargets[slotData.slot_id].hasOwnProperty(key)) {
                    targets.push([key, oldTargets[slotData.slot_id][key]])
                }
            }
        }
        return targets
    }

    function _initLazyLoadHandler(){
        if(_options.lazyLoad){
            if (window.addEventListener) {
                addEventListener('DOMContentLoaded', _debounce(_lazyLoadHandler,60), false);
                addEventListener('scroll', _debounce(_lazyLoadHandler,60), false);
                addEventListener('resize', _debounce(_lazyLoadHandler,60), false);
            } else if (window.attachEvent)  {
                attachEvent('onDOMContentLoaded', _debounce(_lazyLoadHandler,60)); // IE9+ :(
                attachEvent('onscroll', _debounce(_lazyLoadHandler,60));
                attachEvent('onresize', _debounce(_lazyLoadHandler,60));
            }
        }
    }

    function _initOnFocusListeners() {
        var hidden = "hidden";

        // Standards:
        if (hidden in document)
            document.addEventListener("visibilitychange", onchange);
        else if ((hidden = "mozHidden") in document)
            document.addEventListener("mozvisibilitychange", onchange);
        else if ((hidden = "webkitHidden") in document)
            document.addEventListener("webkitvisibilitychange", onchange);
        else if ((hidden = "msHidden") in document)
            document.addEventListener("msvisibilitychange", onchange);
        // IE 9 and lower:
        else if ("onfocusin" in document)
            document.onfocusin = document.onfocusout = onchange;
        // All others:
        else
            window.onpageshow = window.onpagehide
                = window.onfocus = window.onblur = onchange;

        function onchange (evt) {
            var v = true, h = false,
                evtMap = {
                    focus:v, focusin:v, pageshow:v, blur:h, focusout:h, pagehide:h
                };

            evt = evt || window.event;
            if (evt.type in evtMap)
                _isFocused = evtMap[evt.type];
            else
                _isFocused = this[hidden] ? h : v;
        }

        // set the initial state (but only if browser supports the Page Visibility API)
        if( document[hidden] !== undefined )
            onchange({type: document[hidden] ? "blur" : "focus"});
    }

    function _initGPTRenderCompleteListener() {
        addEvent(document, "GPTRenderComplete", function(data) {
            _logDebug("GPT Render Complete", {
                renderEvent: data
            });
            var el = document.getElementById(data.detail.divId);
            if (el && el.className.indexOf("nascarad-rendered") < 0) {
                el.className += " nascarad-rendered"
            }
        })
    }

    function addPageLevelTarget(key, value) {
        _targets.pageTargets[key] = value;
        Googletag.executeWhenAvailable("Adding Page Level Target", function() {
            Googletag.setTargeting(key, value)
        })
    }

    function removePageLevelTarget(key) {
        Googletag.executeWhenAvailable("Removing Page Level Target", function() {
            Googletag.clearTargeting(key);
            if (key) {
                delete _targets.pageTargets[key]
            } else {
                _targets.pageTargets = {};
                if (_testPageTargetKey) {
                    addPageLevelTarget(_testPageTargetKey, _testPageTargetValue)
                }
            }
        })
    }

    function addSlotLevelTarget(slotId, key, value) {
        _targets.slotTargets[slotId] = _targets.slotTargets[slotId] || {};
        _targets.slotTargets[slotId][key] = value;
        Googletag.executeWhenAvailable("Adding Slot Level Target", function() {
            var slot = pageSlots[slotId];
            if (slot) {
                Googletag.setSlotTargeting(slot, key, value)
            }
        })
    }

    // the bug was fixed here, second param was not used
    function removeSlotLevelTarget(slotId, key) {
        Googletag.executeWhenAvailable("Removing Slot Level Target", function() {
            var slot = pageSlots[slotId];
            if (slot) {
                var newTargets = {};
                var keys = slot.getTargetingKeys();
                for (var k in keys) {
                    var value = keys[k];
                    newTargets[value] = slot.getTargeting(value)
                }
                if (key) {
                    delete newTargets[key]
                } else {
                    newTargets = {
                        pos: newTargets.pos
                    }
                }
                Googletag.clearSlotTargeting(slot);
                for (var k in newTargets) {
                    Googletag.setSlotTargeting(slot, k, newTargets[k])
                }
            }
            if (_targets.slotTargets[slotId]) {
                if (key) {
                    delete _targets.slotTargets[slotId][key]
                } else {
                    _targets.slotTargets[slotId].length = 0
                }
            }
        })
    }

    function _setPageLevelTargeting() {
        var cookie = readCookie("gptgeo");
        if (!cookie) {
            _logWarn("Unable to retrieve location cookie", cookie)
        } else {
            var location = cookie.split("%2C");
            var latitude = parseFloat(location[0]);
            var longitude = parseFloat(location[1]);
            Googletag.executeWhenAvailable("setting location", function() {
                Googletag.setLocation(latitude, longitude)
            })
        }
        Googletag.executeWhenAvailable("setting page level targeting", function() {
            var copyOfGlobalPageTargets = _clone(_globalPageTargets);
            var pageTargets = _targets.pageTargets;
            for (var key in pageTargets) {
                if (pageTargets.hasOwnProperty(key)) {
                    copyOfGlobalPageTargets.push([key, pageTargets[key]])
                }
            }
            _logDebug("Page Level Targeting", JSON.stringify(copyOfGlobalPageTargets));
            for (var i = 0; i < copyOfGlobalPageTargets.length; i++) {
                var value = copyOfGlobalPageTargets[i][1];
                _logDebug("Setting Page-Level Targeting", copyOfGlobalPageTargets[i][0], value);
                if (value && !Array.isArray(value)) {
                    if (value.indexOf(",") >= 0) {
                        value = value.split(",")
                    } else {
                        value = [value]
                    }
                }
                if (copyOfGlobalPageTargets[i][0] == "exclusions") {
                    for (var j = 0; j < value.length; j++) {
                        var exclusion = copyOfGlobalPageTargets[i][1][j];
                        Googletag.setCategoryExclusion(exclusion)
                    }
                } else {
                    var key = copyOfGlobalPageTargets[i][0];
                    Googletag.setTargeting(key, value)
                }
            }
        })
    }

    function _updateSlotIfNeeded(slotData) {
        var divs = document.querySelectorAll("div#" + slotData.slot_id);
        if (divs.length != 0) {
            for (var i = 0; i < divs.length; i++) {
                var div = divs[i];
                if (div.className.indexOf("nascarad-rendered") >= 0) {
                    _logDebug("Found rendered slot...", slotData.slot_id)
                } else {
                    if (divs.length == 1 && pageSlots[slotData.slot_id]) {
                        var updatedSlotData = _updateSlotAndDivIdIfNeeded(slotData, true);
                        clearSlot(updatedSlotData.slot_id);
                        return updatedSlotData
                    }
                    return _updateSlotAndDivIdIfNeeded(slotData)
                }
            }
        }
        _logWarn("Not building slot... Can't Find Unrendered Slot On Page", slotData.slot_id);
        return null
    }

    function _buildSlot(slotData) {
        var networkId = _options.networkId;
        _logDebug("Building Slot", slotData);
        var adUnitPath = "/" + networkId + "/" + slotData.adunit_id;
        var slotId = slotData.slot_id;
        var isOutOfPageSlot = (slotData.slot_id.indexOf("_oop") >= 1) || (slotData.slot_id.indexOf("_hover") >= 1);
        var isCompanionSlot = (slotData.slot_id.indexOf("companion") != -1);
        var msg = isOutOfPageSlot ? "Defining OOP Slot" : isCompanionSlot ? "Defining Companion Slot " : "Defining Standard Slot";
        Googletag.executeWhenAvailable(msg, function() {
            if (isOutOfPageSlot) {
                pageSlots[slotId] = Googletag.defineOutOfPageSlot(adUnitPath, slotId)
            } else {
                if (isCompanionSlot){
                    pageSlots[slotId] = Googletag.defineSlot(adUnitPath, slotData.sizes, slotId, true)
                } else {
                    pageSlots[slotId] = Googletag.defineSlot(adUnitPath, slotData.sizes, slotId)
                }
            }
        });
        _logDebug("Slots", pageSlots);
        Googletag.executeWhenAvailable("Defining slot targeting", function() {
            var targets = _getTargets(slotData);
            for (var prop in targets) {
                if (targets.hasOwnProperty(prop)) {
                    var value;
                    if (targets[prop] && targets[prop][1]) {
                        value = JSON.stringify(targets[prop][1])
                    } else {
                        value = ""
                    }
                    if (value) {
                        value = JSON.parse(value);
                        var slot = pageSlots[slotId];
                        if (targets[prop][0] == "exclusions") {
                            if (Array.isArray(targets[prop][1])) {
                                for (var t in targets[prop][1]) {
                                    if (targets[prop][1].hasOwnProperty(t)) {
                                        value = targets[prop][1][t];
                                        Googletag.setSlotCategoryExclusion(slot, value)
                                    }
                                }
                            } else {
                                Googletag.setSlotCategoryExclusion(slot, value)
                            }
                        } else {
                            var key = targets[prop][0];
                            Googletag.setSlotTargeting(slot, key, value)
                        }
                    }
                }
            }
            // Set Slot Level Targetting for Moat Yield Intelligence
            setMoatPrebidData(pageSlots[slotId]);
        });
        if(isOutOfPageSlot){
            _logDebug("Skipping Responsive Mapping For OOP Slot", slotId);
            return;
        }
        _logDebug("Checking Responsive Mapping For Slot", slotData.responsive, slotData.responsive.length);
        slotData.responsive = slotData.responsive || [];
        if (slotData.responsive.length > 0) {
            setSlotSizeMappings(slotData.slot_id, slotData.responsive)
        }
    }

    function _processSlots(filteredSlotsQueue, options) {
        var processedQueueElements = [];

        function __removeFromSlotQueue(queueElement) {
            var index = _slotQueue.indexOf(queueElement);
            if (index >= 0) {
                _slotQueue.splice(index, 1)
            }
        }
        for (var i = 0; i < filteredSlotsQueue.length; i++) {
            var queueElement = filteredSlotsQueue[i];
            var ignoreCheck = options && options.ignoreCheck;
            var isNew = true;
            if (!ignoreCheck) {
                if (!_updateSlotIfNeeded(queueElement)) {
                    __removeFromSlotQueue(queueElement);
                    isNew = false
                }
            }
            if (isNew) {
                _buildSlot(queueElement);
                processedQueueElements.push(queueElement);
                __removeFromSlotQueue(queueElement)
            }
        }
        return processedQueueElements
    }

    function clearSlot(ids) {
        ids = ids || [];
        if (!Array.isArray(ids)) {
            ids = [ids]
        }
        _logDebug("Clearing Slots", {
            slotDivIds: ids
        });
        Googletag.executeWhenAvailable("clearing slots", function() {
            var slots = [];
            if (ids.length > 0) {
                slots = ids.filter(function(id) {
                    return !!pageSlots[id]
                }).map(function(id) {
                    return pageSlots[id]
                });
                if (slots.length == 0) {
                    return
                }
            }
            Googletag.clearSlots(slots)
        })
    }

    function destroySlot(ids) {
        ids = ids || [];
        if (!Array.isArray(ids)) {
            ids = [ids]
        }
        _logDebug("Destroying Slots", {
            slotDivIds: ids
        });
        Googletag.executeWhenAvailable("destroying slots", function() {
            var slots = [];
            if (ids.length > 0) {
                slots = ids.filter(function(id) {
                    return !!pageSlots[id];
                }).map(function(id) {
                    return pageSlots[id];
                });
                if (slots.length == 0) {
                    return;
                }
            }

            Googletag.destroySlots(slots);

            if(slots.length >0){
                for(var i=0; i<ids.length;i++){
                    if(!!pageSlots[id[i]]){
                        _clearSlotDiv(id[i]);
                        delete pageSlots[id[i]];
                    }
                }
            } else {
                _clearAllSlotsDivs();
                pageSlots = {};
            }

        })
    }

    function _clearSlotDiv(id){
        var divs = window.document.querySelectorAll('div#' + id);
        for(var i =0;i<divs.length;i++){
            divs[i].className = divs[i].className.replace('nascarad-rendered','');
        }
    }

    function _clearAllSlotsDivs(){
        var divs = window.document.querySelectorAll('div.nascarad-rendered');
        for(var i =0;i<divs.length;i++){
            divs[i].className = divs[i].className.replace('nascarad-rendered','');
        }
    }

    function setSlotSizeMappings(slotId, mappingsData) {
        for (var i = 0; i < mappingsData.length; i++) {
            var mappingData = JSON.parse(JSON.stringify(mappingsData[i]));
            for (var j = 0; j < mappingData.length; j++) {
                if (Array.isArray(mappingData[j])) {
                    for (var k = 0; k < mappingData[j].length; k++) {
                        if (Array.isArray(mappingData[j][k])) {
                            for (var m = 0; m < mappingData[j][k].length; m++) {
                                mappingData[j][k][m] = parseInt(mappingData[j][k][m])
                            }
                        } else {
                            if (parseInt(mappingData[j][k]) >= 0) {
                                mappingData[j][k] = parseInt(mappingData[j][k])
                            } else {
                                mappingData[j] = []
                            }
                        }
                    }
                } else {
                    mappingData[j] = []
                }
            }
            mappingsData[i] = mappingData
        }
        Googletag.executeWhenAvailable("setting slot mappings", function() {
            Googletag.defineSlotSizeMapping(pageSlots[slotId], mappingsData)
        })
    }

    function _updateSlotAndDivIdIfNeeded(slotData, flag) {
        _logDebug("Checking to see if slot div id needs updated.", {
            slot: slotData
        });
        var arr = slotData.slot_id.split("_");
        var index = arr[arr.length - 1];
        var oldId = arr.join("_");
        var newId = "";
        var divs;
        if (arr.length == 3) {
            divs = document.querySelectorAll("div#ad_mod_" + oldId)
        } else {
            divs = document.querySelectorAll("div#" + oldId)
        }
        if (divs.length > 1 || (divs.length == 1 && flag)) {
            newId = oldId;
            var slot = pageSlots[newId];
            while (slot) {
                newId = JSON.parse(JSON.stringify(oldId));
                if (arr.length == 3) {
                    index = generateSingletonId()
                } else {
                    index = parseInt(index) + 1;
                    if (index < 10) {
                        index = "0" + String(index)
                    } else {
                        index = String(index)
                    }
                }
                arr[arr.length - 1] = index;
                newId = arr.join("_");
                slot = pageSlots[newId];
                if (!slot) {
                    _changeSlotId(slotData, newId, oldId);
                    _updateSlotTargeting(slotData, "pos" ,newId);
                    _changeDivId(oldId, newId);
                    break
                }
            }
        }
        return slotData
    }

    function _updateSlotTargeting(slotData, key, value){
        if(slotData && slotData.targeting && typeof slotData.targeting.length === "number"){
            var index = null;
            for(var i = 0; i<slotData.targeting.length; i++){
                if(slotData.targeting[i].length === "number" && slotData.targeting[i][0] === key){
                    index = i;
                    break;
                }
            }

            if(typeof index === "number"){
                slotData.targeting[index][1] = [value];
            } else {
                slotData.targeting.push([key,[value]]);
            }
        }
    }

    function _changeSlotId(slotData, newId, oldId) {
        slotData.slot_id = newId;
        try {
            var event = new CustomEvent("SlotIdChange", {
                detail: {
                    asset: slotData,
                    originalId: oldId,
                    newId: newId
                }
            });
            document.dispatchEvent(event)
        } catch (error) {
            _logWarn("error dispatching custom Event: SlotIdChange", error)
        }
    }

    function _changeDivId(oldId, newId) {
        var divs = document.querySelectorAll("div#" + oldId);
        if (divs.length > 0) {
            for (var i = 0; i < divs.length; i++) {
                var div = divs[i];
                if ((div.className.indexOf("nascarad-rendered") < 0 && divs.length > 1) || divs.length == 1) {
                    div.id = newId
                }
            }
        }
    }

    function _isReady() {
        return _isNascarAdInitiated && _isDomReady
    }

    function _dispatchQueueOnceReady() {
        if (_isReady()) {
            if (_dispatchQueue.length > 0) {
                for (var i = 0; i < _dispatchQueue.length; i++) {
                    _dispatchQueue[i]()
                }
                _dispatchQueue.length = 0
            } else {
                if (_options.autoDispatch) {
                    NascarAd.dispatchQueue()
                }
            }
        }
    }

    var _videoAdTagData = null;
    var _VIDEO_AD_TAG_TEMPLATE = 'https://pubads.g.doubleclick.net/gampad/ads?ppid='+_getPIDPageTargeting()+'&sz=[sizes][companionsSizes][targeting]&iu=[ad_unit]&impl=s&gdfp_req=1&env=vp&output=vast&unviewed_position_start=1&url=[referrer_url]&description_url=https%3A%2F%2Fnascar.com'+window.location.pathname+'&correlator=[timestamp]&vid={mediainfo.id}';
    var _COMPANION_SIZES_TAG_PART_TEMPLATE = '&ciu_szs=[companionsSizes]';
    var _TARGETING_TAG_PART_TEMPLATE = '&cust_params=[targeting]';
    function createVideoAdTag(){
        if(!_videoAdTagData || _videoAdTagData.videoAndCompanionSlots.video.length < 1 || !_videoAdTagData.adId){
            _logDebug("No video ad on the page");
            return;
        }

        var adUnit = '/' + _options.networkId + '/' + _videoAdTagData.adId;
        var videoSlotsizes = _collectUniqueSizes(_videoAdTagData.videoAndCompanionSlots.video[0]);
        var sizes = videoSlotsizes ? videoSlotsizes.split(',').join('|').replace(/X/ig, 'x') : 'none';

        var companionSlotsSizes = '';
        for (var i = 0; i<_videoAdTagData.videoAndCompanionSlots.companion.length; i++){
            companionSlotsSizes += _collectUniqueSizes(_videoAdTagData.videoAndCompanionSlots.companion[i]) + ',';
        }

        var targeting = _createVideoTargeting(_videoAdTagData.videoAndCompanionSlots.video[0]);

        companionSlotsSizes = companionSlotsSizes ? _removeNone(_removeDuplicateSizes(_cutOffLastSimbol(companionSlotsSizes))) : '';
        try {
            if (nascarBrightCoveCmsid && !(_VIDEO_AD_TAG_TEMPLATE.indexOf('cmsid')>-1)) {
                _VIDEO_AD_TAG_TEMPLATE = _VIDEO_AD_TAG_TEMPLATE + '&cmsid=' + nascarBrightCoveCmsid;
            }
        }catch(e){
            console.log('nascarBrightCoveCmsid is not defined');
        }
        return _VIDEO_AD_TAG_TEMPLATE
            .replace('[referrer_url]', encodeURIComponent(_preparePageURL()))
            .replace('[sizes]', sizes)
            .replace('[ad_unit]', adUnit)
            .replace('[companionsSizes]', companionSlotsSizes
                ? _COMPANION_SIZES_TAG_PART_TEMPLATE.replace('[companionsSizes]', companionSlotsSizes.toLowerCase())
                : '')
            .replace('[targeting]', targeting
                ? _TARGETING_TAG_PART_TEMPLATE.replace('[targeting]', targeting)
                : '' );
    }

    function _createVideoTargeting(slotDate){
        _updatePIDPageTargeting();
        var copyOfGlobalPageTargets = _clone(_globalPageTargets);
        var pageTargets = _targets.pageTargets;
        for (var key in pageTargets) {
            if (pageTargets.hasOwnProperty(key)) {
                copyOfGlobalPageTargets.push([key, pageTargets[key]])
            }
        }

        var slotTargeting = _getTargets(slotDate);
        for (var i = 0; i < slotTargeting.length; i++) {
            copyOfGlobalPageTargets.push(slotTargeting[i]);
        }

        var targeting = '';
        if(copyOfGlobalPageTargets.length > 0){
            for (var i = 0; i < copyOfGlobalPageTargets.length; i++) {
                var key, value;
                if (copyOfGlobalPageTargets[i][0] != "exclusions") {
                    value = copyOfGlobalPageTargets[i][1];
                    if(Array.isArray(value)){
                        value = value.join(',');
                    }
                    key = copyOfGlobalPageTargets[i][0];
                    targeting+= key + '%3D' + value.replace(/,/ig,'%2C') + '%26';
                }
            }
            targeting = targeting.substring(0,targeting.length-3);
        }
        if (window.moatPrebidApi && typeof window.moatPrebidApi.slotDataAvailable === 'function') {
            var mData= moatPrebidApi.getMoatTargetingForPage();
            var tempData = '';
            for( var i in mData ) {
                tempData = tempData +'%26'+i+'%3D'+ mData[i];
            }
            if(tempData != ''){
                targeting = targeting +tempData;
            }
        }
        _logDebug("Video targetings:", targeting);
        return targeting;
    }

    function _loadSlotsData(){
        var adUnitId = _getParamValue("adunitid");
        if( !adUnitId && typeof NascarAdAdUnitId !== 'undefined' && (NascarAdAdUnitId || NascarAdAdUnitId === 0) ){
            adUnitId = NascarAdAdUnitId;
        }

        if(adUnitId){
           var domain = 'www.nascar.com';
           if(window.location.href.indexOf(".stage-editor")>-1){
                domain= "nascar.stage-editor.ndms.nascar.com";
            }
            _ajax({
                url: adTagProtocol+'//'+domain+'/adunit/'+adUnitId+'/'
            }).then(function(error, data, xhr){
                if(error){
                    _hendleAjaxError(error,xhr);
                } else {
                    _logDebug("AJAX data", data);
                    data = _adjustData(data);
                    _logDebug("Adjusted AJAX data", data);
                    NascarAd.registry.push(data);
                }
            });

        } else {
            _logError('Request parameter "adunitid" is blank and global var NascarAdAdUnitId is undefined, cannot load ad.')
        }

    }

    function _adjustData(data){
        var result = [], slotData, adUnitData, adId, videoAndCompanionSlots;

        adUnitData = data[0];
        adId = _adunitnameToAdId(adUnitData.adunitname);
        videoAndCompanionSlots = _findVideoAndCompanionSlots(data);
        _videoAdTagData = {
            videoAndCompanionSlots:videoAndCompanionSlots,
            adId:adId
        };
        var entry = {
            slot_id: 'page',
            adunit_name: adUnitData.adunitname,
            gpt_id: _options.networkId,
            root: 'NASCAR',
            site: 'nascar',
            targeting:[]
        };
        result.push(entry);

        for(var i = 0, l = data[0].adslot.length; i < l ; i++){
            slotData = data[0].adslot[i];
            if(slotData.slotid.indexOf('video') == -1){
                entry = {
                    slot_id: slotData.slotid,
                    adunit_id: adId,
                    sizes: _collectSizes(slotData),
                    hasInViewRefresh: "false",
                    inViewRefreshCount: "5",
                    inViewRefreshInterval: "35",
                    targeting: _getSlotTargeting(slotData),
                    responsive: _collectResponsive(slotData)
                };
                result.push(entry);
            }
        }

        return result;
    }

    function _findVideoAndCompanionSlots(data){
        var slotData,
            videoAndCompanionSlots = {
                video:[],
                companion:[]
            };

        for(var i = 0, l = data[0].adslot.length; i < l ; i++){
            slotData = data[0].adslot[i];
            if(slotData.slotid.indexOf('video') != -1){
                slotData.targeting = _getSlotTargeting(slotData);
                videoAndCompanionSlots.video.push(slotData)
            } else if (slotData.slotid.indexOf('companion') != -1){
                videoAndCompanionSlots.companion.push(slotData)
            }
        }

        return videoAndCompanionSlots;
    }

    function _adunitnameToAdId(adunitname){
        var arr = adunitname.split('_');
        if( arr[0] && arr[0].toLowerCase() === 'nascar'){
            arr[0] = arr[0].toUpperCase();
        }
        return arr.join("/")
    }

    function _collectSizes(slotData){
        var slotsizes = _collectUniqueSizes(slotData);

        // create dfp sizes
        return _slotsizesToSizes(slotsizes);
    }

    function _collectUniqueSizes(slotData){
        var slotsizes = '';

        for (var i = 0, l = _devices.length; i<l; i++){
            if( slotData.hasOwnProperty(_devices[i].key) && slotData[_devices[i].key] && slotData[_devices[i].key].toUpperCase() != 'NONE'){
                slotsizes += slotData[_devices[i].key] + ',';
            }
        }

        slotsizes = _cutOffLastSimbol(slotsizes);

        return _removeDuplicateSizes(slotsizes);
    }

    function _removeDuplicateSizes(slotsizes){
        var uniqueCheck = '', arr;

        arr = slotsizes.split(',');
        for(var i = 0; i< arr.length ; i ++ ){
            if (uniqueCheck.indexOf(arr[i]) == -1){
                uniqueCheck += arr[i] + ',';
            }
        }

        return _cutOffLastSimbol(uniqueCheck);
    }

    function _removeNone(slotsizes){
        var indexes =[], arr = slotsizes.split(',');

        for(var i = 0; i<arr.length; i++){
            if(arr[i].toLowerCase() == 'none'){
                indexes.push(i);
            }
        }

        if(indexes.length > 0) {
            indexes.sort();
            indexes.reverse();
            for (var i = 0; i < indexes.length; i++) {
                arr.splice(indexes[i], 1);
            }
        }

        return arr.join(',');
    }

    function _slotsizesToSizes(slotsizes){
        var sizes = [], size, uniqueCheck = '';

        _logDebug("Sizes string:" + slotsizes);
        slotsizes = slotsizes || '';

        var arr = slotsizes.split(',');
        for(var i = 0; i< arr.length ; i ++ ){
            if (uniqueCheck.indexOf(arr[i]) == -1){
                uniqueCheck += arr[i] + ',';

                size = arr[i].indexOf('X') != -1 ? arr[i].split('X') : arr[i].split('x');
                size[0] = parseInt(size[0]);
                size[1] = parseInt(size[1]);
                sizes.push(size);
            }
        }

        _logDebug("Unique sizes string: " + _cutOffLastSimbol(uniqueCheck));
        return sizes;
    }

    function _cutOffLastSimbol(str){
        return ( typeof str === 'string' && str.length > 0 ) ? str.substring(0, str.length - 1) : str;
    }

    function _getTargetingPosFromSlotId(slotId){
        var arr = slotId.split('_');
        return arr.splice(1,arr.length).join('_');
    }

    function _getSlotTargeting(slotData){
        var slotTargeting = [], arr, targeting;
        slotTargeting.push(['pos',[slotData.slotid]]);
        if(slotData['slottargeting'] && slotData['slottargeting'].trim().toLowerCase() != 'none'){
            arr = slotData['slottargeting'].split('|');
            if(arr.length > 0){
                for(var i= 0;i<arr.length;i++){
                    targeting = arr[i].split("=");
                    if(targeting.length != 2){
                        continue;
                    }
                    targeting[0] = targeting[0].replace(/[^\w\d\s]/ig,'').trim().replace(/\s/ig,'_');
                    targeting[1] = targeting[1].replace(/[^\w\d\s]/ig,'').trim().replace(/\s/ig,'_');
                    if(targeting[0] && targeting[1]){
                        slotTargeting.push([targeting[0], [targeting[1]]]);
                    }
                }
            }
        }
        return slotTargeting;
    }

    function _collectResponsive(slotData){
        var responsive = [], slotsizes;

        for (var i=0;i<_devices.length; i++){
            if( slotData.hasOwnProperty(_devices[i].key) && slotData[_devices[i].key] && slotData[_devices[i].key].toUpperCase() != 'NONE') {
                slotsizes = slotData[_devices[i].key];
                responsive.push([ _devices[i].screenSize , _slotsizesToSizes(slotsizes) ]);
            } else {
                responsive.push( [ _devices[i].screenSize , ['suppress'] ]);
            }
        }

        return responsive;
    }

    function requestAndRenderAds(options) {
        if (!_isReady()) {
            _logDebug("Delaying Queue Dispatch");
            _dispatchQueue.push(function() {
                requestAndRenderAds(options)
            });
            return
        }
        options = options || {};
        _logDebug("Registry", NascarAd.registry);
        _logDebug("SlotQueue: ", _slotQueue);
        _logDebug("Dispatch Options: ", options);
        if (_slotQueue.length > 0) {
            var filteredSlots = _slotQueue.filter(function(slot) {
                return ((!options.slots || options.slots.length == 0 || options.slots.indexOf(slot.slot_id) >= 0) && (!options.exclude || options.exclude.length == 0 || options.exclude.indexOf(slot.slot_id) < 0) && ((options.slots && options.slots.length > 0) || _excludes.indexOf(slot.slot_id) < 0))
            });
            if (options.slots && options.slots.length > 0 && _excludes.length > 0) {
                for (var i = 0; i < options.slots.length; i++) {
                    var ay = _excludes.indexOf(options.slots[i]);
                    if (ay >= 0) {
                        _excludes.splice(ay, 1)
                    }
                }
            }

            var copyOfFilteredSlots = _clone(filteredSlots);
            var preSlotProcessCallbacks = _modules.filter(function(module) {
                return !!module.callbacks.preSlotProcessCallback
            }).map(function(module) {
                return _callbackObjectBuilder(module.name, function(data) {
                    module.callbacks.preSlotProcessCallback(copyOfFilteredSlots, data)
                })
            });
            if (options && options.preSlotProcessCallback) {
                preSlotProcessCallbacks.push(_callbackObjectBuilder("dispatchOptions", function(data) {
                    options.preSlotProcessCallback(copyOfFilteredSlots, data)
                }))
            }
            async.parallelWithTimeout("preProcessSlot", _options.dispatchCallbackTimeoutInMilliseconds, preSlotProcessCallbacks, function(msg) {
                if (msg) {
                    _logWarn("error calling preSlotProcessCallbacks for registered modules", msg)
                }
                var processedSlots = _processSlots(filteredSlots, options);
                if (processedSlots.length > 0) {
                    _setPageLevelTargeting();
                    var copyOfProcessedSlots = _clone(processedSlots);
                    var preDispatchCallbacks = _modules.filter(function(module) {
                        return !!module.callbacks.preDispatchCallback
                    }).map(function(module) {
                        return _callbackObjectBuilder(module.name, function(data) {
                            module.callbacks.preDispatchCallback(copyOfProcessedSlots, data)
                        })
                    });
                    if (options && options.preDispatchCallback) {
                        preDispatchCallbacks.push(_callbackObjectBuilder("dispatchOptions", function(data) {
                            options.preDispatchCallback(copyOfProcessedSlots, data)
                        }))
                    }
                    async.parallelWithTimeout("preDispatch", _options.dispatchCallbackTimeoutInMilliseconds, preDispatchCallbacks, function(msg) {
                        if (msg) {
                            _logWarn("error calling preDispatchCallbacks for registered modules", msg)
                        }
                        var displayedSlots = _displaySlots(processedSlots, options);
                        var copyOfDisplayedSlots = _clone(displayedSlots);
                        var postDispatchCallbacks = _modules.filter(function(module) {
                            return !!module.callbacks.postDispatchCallback
                        }).map(function(module) {
                            return _callbackObjectBuilder(module.name, function(data) {
                                module.callbacks.postDispatchCallback(copyOfDisplayedSlots, data)
                            })
                        });
                        if (options && options.postDispatchCallback) {
                            postDispatchCallbacks.push(_callbackObjectBuilder("dispatchOptions", function(data) {
                                options.postDispatchCallback(copyOfDisplayedSlots, data)
                            }))
                        }
                        async.parallelWithTimeout("postDispatch", _options.dispatchCallbackTimeoutInMilliseconds, postDispatchCallbacks, function(msg) {
                            if (msg) {
                                _logWarn("error calling postDispatchCallbacks for registered modules", msg)
                            }
                            _logDebug("Slot Queue After Dispatch:", _slotQueue)
                        })
                    })
                }
            });
        }
    }

    // JSONP call to load slots config
    function queueRegistry(url, options) {
        options = options || {
                dispatch: _options.autoDispatch
            };
        if (options.exclude && options.exclude.length > 0) {
            for (var i = 0; i < options.exclude.length; i++) {
                var exclude = options.exclude[i];
                if (_excludes.indexOf(exclude) < 0) {
                    _excludes.push(exclude)
                }
            }
        }

        function __c() {
            if (options.dispatch) {
                NascarAd.dispatchQueue(options)
            }
        }(function(callback) {
            var d = document,
                s = d.createElement("script"),
                p = d.getElementsByTagName("script")[0],
                r = /^(complete|loaded)$/,
                f = false;
            s.type = "text/javascript";
            s.src = url;
            s.onload = s.onreadystatechange = function() {
                if (!f && !(("readyState" in s) && r.test(s.readyState))) {
                    s.onload = s.onreadystatechange = null;
                    f = true;
                    callback()
                }
            };
            p.parentNode.insertBefore(s, p)
        })(__c)
    }

    function queueRegistryAjax(url, options) {
        options = options || {
                dispatch: _options.autoDispatch
            };
        if (options.exclude && options.exclude.length > 0) {
            for (var i = 0; i < options.exclude.length; i++) {
                var exclude = options.exclude[i];
                if (_excludes.indexOf(exclude) < 0) {
                    _excludes.push(exclude)
                }
            }
        }

        _ajax({
            url:url,
            withCredentials:false
        }).then(function(error, data, xhr){
            if(error){
                _hendleAjaxError(error,xhr);
            } else {
                if(options.destroyAllSlots){
                    NascarAd.destroySlots();
                }
                _logDebug("AJAX data", data);
                data = _adjustData(data);
                _logDebug("Adjusted AJAX data", data);
                NascarAd.registry.push(data);
                NascarAd.dispatchQueue(options);
            }
        });
    }

    function buildSlotsAjax(url, slots) {
        // get the List of the Slots that are not in the page slots json
        var newSlots=[];
        var isExistingSlot=false;
        for(var i=0;i<slots.length;i++){
            isExistingSlot=false;
            for (var id in pageSlots) {
                if (pageSlots.hasOwnProperty(slots[i])) {
                    isExistingSlot = true;
                    break;
                }
            }
            if(!isExistingSlot){
                newSlots.push(slots[i]);
            }
        }
        _ajax({
            url:url,
            withCredentials:false
        }).then(function(error, data, xhr){
            if(error){
                _hendleAjaxError(error,xhr);
            } else {
                _logDebug("AJAX data", data);
                data = _adjustData(data);
                _logDebug("Adjusted AJAX data", data);
                var sName = "";
                var sData = null;
                for(var i=0;i<data.length;i++){
                    sName = data[i].slot_id;
                    if(newSlots.indexOf(sName) > -1 ){
                        _buildSlot(data[i]);
                    }
                }
            }
        });
    }

    function _setInterval(interval, numberFoTimes, callback) {
        numberFoTimes = numberFoTimes || 10;
        var delta = interval / numberFoTimes,
            counter = 0,
            now = new Date().getTime();

        function _callback() {
            if (counter++ == numberFoTimes) {
                var flag = callback();
                if (flag) {
                    _setInterval(interval, numberFoTimes, callback)
                }
            } else {
                var t = (new Date().getTime() - now) - (counter * delta);
                window.setTimeout(_callback, (delta - t))
            }
        }
        window.setTimeout(_callback, delta)
    }

    function refresh(ids, options) {
        if (ids && typeof ids == "object" && !options) {
            options = ids;
            ids = []
        } else {
            options = options || {}
        }
        if (!ids) {
            ids = []
        }
        options.pageload = (options.pageload == undefined) ? true : options.pageload;
        _logDebug("Refresh Options", options);
        var __callback = function() {
            if (_isFocused || !_options.refreshOnFocusOnly) {
                var slotsToRefresh = [];
                var idsToRefresh = [];
                var arr = [];
                if (ids.length == 0) {
                    for (var id in pageSlots) {
                        if (pageSlots.hasOwnProperty(id)) {
                            arr.push(id)
                        }
                    }
                } else {
                    arr = ids
                }
                for (var i = 0; i < arr.length; i++) {
                    var id = arr[i];
                    if (document.getElementById(id)) {
                        var slotToRefresh = pageSlots[id];
                        if (slotToRefresh) {
                            slotsToRefresh.push(slotToRefresh);
                            idsToRefresh.push(id)
                        }
                    } else {
                        _logWarn("Cannot find element on page to refresh: " + id)
                    }
                }
                if (ids.length > 0 && idsToRefresh.length == 0) {
                    return
                }
                var preRefreshCallbacks = _modules.filter(function(module) {
                    return !!module.callbacks.preRefreshCallback
                }).map(function(module) {
                    return _callbackObjectBuilder(module.name, function(data) {
                        module.callbacks.preRefreshCallback(idsToRefresh, data)
                    })
                });
                if (options.preRefreshCallback) {
                    preRefreshCallbacks.push(_callbackObjectBuilder("refreshOptions", function(data) {
                        options.preRefreshCallback(idsToRefresh, data)
                    }))
                }
                async.parallelWithTimeout("preRefresh", _options.refreshCallbackTimeoutInMilliseconds, preRefreshCallbacks, function(msg) {
                    if (msg) {
                        _logWarn("error calling preRefreshCallbacks for all registered modules", msg)
                    }
                    clearSlot(idsToRefresh);
                    Googletag.updateCorrelator();
                    if (options.pageload) {
                        Googletag.setTargeting("pageload", "ref")
                    } else {
                        Googletag.clearTargeting("pageload")
                    }
                    Googletag.refreshSlots(slotsToRefresh);
                    var copyOfIdsToRefresh = idsToRefresh;
                    var postRefreshCallbacks = _modules.filter(function(module) {
                        return !!module.callbacks.postRefreshCallback
                    }).map(function(module) {
                        return _callbackObjectBuilder(module.name, function(data) {
                            module.callbacks.postRefreshCallback(copyOfIdsToRefresh, data)
                        })
                    });
                    if (options.postRefreshCallback) {
                        postRefreshCallbacks.push(_callbackObjectBuilder("refreshOptions", function(data) {
                            options.postRefreshCallback(copyOfIdsToRefresh, data)
                        }))
                    }
                    async.parallelWithTimeout("postRefresh", _options.refreshCallbackTimeoutInMilliseconds, postRefreshCallbacks, function(msg) {
                        if (msg) {
                            _logWarn("error calling postRefreshCallbacks for all registered modules", msg)
                        }
                    })
                })
            }
        };

        function __runner(sec) {
            _logDebug("starting refresh interval: " + sec, options);
            var interval = sec * 1000;
            _setInterval(interval, 5, function() {
                __callback();
                if (!options.interval || parseInt(options.interval) == 0) {
                    _logDebug("stopping refresh interval: " + sec, options);
                    return false
                }
                var i = parseInt(options.interval);
                if (sec != i) {
                    _logDebug("changing refresh interval: " + sec, options);
                    __runner(i);
                    return false
                }
                return true
            })
        }
        if (options.interval && parseInt(options.interval) > 0) {
            var interval = parseInt(options.interval);
            __runner(interval)
        } else {
            __callback()
        }
    }

    function _preparePageURL(){
        var builder = [
            window.location.protocol,
            "//",
            window.location.host,
            (window.location.port? ":" + window.location.port : ""),
            window.location.pathname];

        var test = _getParamValue("test") ? "test="+_getParamValue("test") : "";
        var franchiseName = _getParamValue("franchiseName") ? "franchiseName="+_getParamValue("franchiseName") : "";

        if (test && franchiseName){
            builder.push("?" + test + "&" + franchiseName);
        } else {
            if (test){
                builder.push("?" + test);

            } else if (franchiseName){
                builder.push("?" + franchiseName);
            }
        }
        return builder.join("");
    }

    var Googletag = function() {
        window.googletag = window.googletag || {};
        window.googletag.cmd = window.googletag.cmd || [];
        var isPubAdsConfigured = false;
        var _isGPTReady = false;

        function isAvailable(message, object) {
            if (!_isGPTReady) {
                _isGPTReady = window.googletag.apiReady && window.googletag.pubads;
                if (!_isGPTReady && message) {
                    _logError("GPT is unavailable - " + message, object)
                }
            }
            return _isGPTReady
        }

        function executeWhenAvailable(message, callback) {
            window.googletag.cmd.push(callback)
        }

        function configurePubAds() {
            if (!isPubAdsConfigured) {
                var ppid= _getPIDPageTargeting();
                isPubAdsConfigured = true;
                NascarAd.requestScriptText += "googletag.companionAds().setRefreshUnfilledSlots(true);\n";
                NascarAd.requestScriptText += "googletag.pubads().collapseEmptyDivs(true);\n";
                NascarAd.requestScriptText += "googletag.pubads().enableAsyncRendering();\n";
                NascarAd.requestScriptText += "googletag.pubads().enableSingleRequest();\n";
                NascarAd.requestScriptText += "googletag.pubads().disableInitialLoad();\n";
                NascarAd.requestScriptText += "googletag.pubads().setPublisherProvidedId('"+ ppid+"');\n";
                NascarAd.requestScriptText += "googletag.enableServices();\n";
                executeWhenAvailable("Sending Request", function aR() {
                    window.googletag.pubads().addEventListener("slotRenderEnded", function(e) {
                        try {
                            var slot = {};
                            if (e.slot) {
                                slot.asset = e.slot
                            }
                            if (e.slot.getTargeting("pos")) {
                                slot.pos = e.slot.getTargeting("pos")
                            }
                            if (e.isEmpty) {
                                slot.empty = true
                            } else {
                                slot.empty = false
                            }
                            if (e.size) {
                                slot.renderedSize = e.size
                            }
                            if (e.creativeId) {
                                slot.creativeId = e.creativeId
                            }
                            if (e.lineItemId) {
                                slot.lineItemId = e.lineItemId
                            }
                            if (e.serviceName) {
                                slot.serviceName = e.serviceName
                            }
                            if (e.slot.getSlotElementId()) {
                                slot.divId = e.slot.getSlotElementId()
                            }
                            _logDebug("GPTRenderComplete Details: ", slot);
                            var event = new CustomEvent("GPTRenderComplete", {
                                detail: slot
                            });
                            document.dispatchEvent(event)
                        } catch (error) {
                            _logWarn("error dispatching custom Event: GPTRenderComplete", error)
                        }
                    });
                    window.googletag.companionAds().setRefreshUnfilledSlots(true);
                    window.googletag.pubads().set("page_url", _preparePageURL());
                    window.googletag.pubads().collapseEmptyDivs(true);
                    window.googletag.pubads().enableAsyncRendering();
                    window.googletag.pubads().enableSingleRequest();
                    window.googletag.pubads().disableInitialLoad();
                    window.googletag.pubads().setPublisherProvidedId( ppid+'');
                    window.googletag.enableServices()
                })
            }
        }

        function clearTargeting(key) {
            var flag = false;
            if (isAvailable("clearing target", {
                    key: (!!key ? key : "all")
                })) {
                if (key) {
                    window.googletag.pubads().clearTargeting(key)
                } else {
                    window.googletag.pubads().clearTargeting()
                }
                flag = true
            }
            return flag
        }

        function setTargeting(key, value) {
            var flag = false;
            if (isAvailable("setting target", {
                    key: key,
                    value: value
                })) {
                window.googletag.pubads().setTargeting(key, value);
                flag = true
            }
            return flag
        }

        function setLocation(latitude, longitude) {
            var flag = false;
            if (isAvailable("setting location", {
                    latitude: latitude,
                    longitude: longitude
                })) {
                window.googletag.pubads().setLocation(latitude, longitude);
                flag = true
            }
            return flag
        }

        function setCategoryExclusion(category) {
            var flag = false;
            if (isAvailable("setting category exclusion: " + category)) {
                NascarAd.requestScriptText += "googletag.pubads().setCategoryExclusion('" + category + "');\n";
                window.googletag.pubads().setCategoryExclusion(category);
                flag = true
            }
            return flag
        }

        function updateCorrelator() {
            var flag = false;
            if (isAvailable("updating correlator")) {
                NascarAd.requestScriptText += "googletag.pubads().updateCorrelator();\n";
                window.googletag.pubads().updateCorrelator();
                flag = true
            }
            return flag
        }

        function defineOutOfPageSlot(adPath, slotId) {
            var slot;
            if (isAvailable("defining out of page slot", {
                    adPath: adPath,
                    slotId: slotId
                })) {
                _logDebug("Building OOP Slot Object", {
                    adPath: adPath,
                    slotId: slotId
                });
                NascarAd.requestScriptText += "\n_pageSlots['" + slotId + "'] = googletag.defineOutOfPageSlot('" + adPath + "', '" + slotId + "').addService(googletag.pubads());\n";
                slot = window.googletag.defineOutOfPageSlot(adPath, slotId).addService(window.googletag.pubads())
            }
            return slot
        }

        function defineSlot(adPath, sizes, slotId, isCompanion) {
            var slot;
            if (isAvailable("defining standard slot", {
                    adPath: adPath,
                    sizes: sizes,
                    slotId: slotId
                })) {
                _logDebug("Building Standard Slot Object", {
                    adPath: adPath,
                    sizes: sizes,
                    slotId: slotId
                });
                NascarAd.requestScriptText += "\n_pageSlots['" + slotId + "'] = googletag.defineSlot('" + adPath + "', " + JSON.stringify(sizes) + ", '" + slotId + "')\n";
                slot = window.googletag.defineSlot(adPath, sizes, slotId);
                if(isCompanion) {
                    NascarAd.requestScriptText += ".addService(googletag.companionAds())";
                    slot.addService(window.googletag.companionAds());
                }
                NascarAd.requestScriptText += ".addService(googletag.pubads())";
                slot.addService(window.googletag.pubads());
                NascarAd.requestScriptText += ";\n";
            }
            return slot
        }

        function setSlotCategoryExclusion(slot, category) {
            var slotId = slot.getSlotElementId();
            _logDebug("Setting Slot Category Exclusion", {
                slotId: slotId,
                value: category
            });
            NascarAd.requestScriptText += "_pageSlots['" + slotId + "'].setCategoryExclusion('" + category + "');\n";
            slot.setCategoryExclusion(category)
        }

        function setSlotTargeting(slot, key, value) {
            var slotId = slot.getSlotElementId();
            _logDebug("Setting Slot Targeting", {
                slotId: slotId,
                key: key,
                value: value
            });
            NascarAd.requestScriptText += "_pageSlots['" + slotId + "'].setTargeting('" + key + "', '" + value + "');\n";
            slot.setTargeting(key, value)
        }

        function defineSlotSizeMapping(slot, sizeMapping) {
            var slotId = slot.getSlotElementId();
            _logDebug("Setting Slot size mapping", {
                slotId: slotId,
                responsiveMap: sizeMapping
            });
            NascarAd.requestScriptText += "_pageSlots['" + slotId + "'].defineSizeMapping('" + JSON.stringify(sizeMapping) + "');\n";
            slot.defineSizeMapping(sizeMapping)
        }

        function displaySlotById(slot) {
            _logDebug("Displaying Slot: " + slot);
            NascarAd.requestScriptText += 'googletag.display("' + slot + '");\n';
            window.googletag.display(slot)
        }

        function clearSlotTargeting(slot) {
            var slotId = slot.getSlotElementId();
            _logDebug("Clearing targeting for Slot: " + slotId);
            NascarAd.requestScriptText += "_pageSlots['" + slotId + "'].clearTargeting();\n";
            slot.clearTargeting()
        }

        function clearSlots(slots) {
            var slotsIds = (slots.length == 0) ? "all" : slots.map(function(slot) {
                return slot.getSlotElementId()
            }).join(",");
            NascarAd.requestScriptText += "googletag.pubads().clear(" + slotsIds + ");\n";
            if (slots.length > 0) {
                window.googletag.pubads().clear(slots)
            } else {
                window.googletag.pubads().clear()
            }
        }

        function destroySlots(slots) {
            var slotsIds = (slots.length == 0) ? "all" : slots.map(function(slot) {
                return slot.getSlotElementId()
            }).join(",");
            NascarAd.requestScriptText += "googletag.destroySlots(" + slotsIds + ");\n";
            if (slots.length > 0) {
                window.googletag.destroySlots(slots)
            } else {
                window.googletag.destroySlots()
            }
        }
        function refreshSlots(slots, changeCorrelator) {
            var slotsIds = (slots.length == 0) ? "all" : slots.map(function(slot) {
                return slot.getSlotElementId()
            }).join(",");
            NascarAd.requestScriptText += "googletag.pubads().refresh(" + slotsIds + ");\n";
            if (slots.length > 0) {
                var settings = {changeCorrelator: changeCorrelator};
                (typeof changeCorrelator === "boolean") ?
                    window.googletag.pubads().refresh(slots, settings) :
                    window.googletag.pubads().refresh(slots);
            } else {
                window.googletag.pubads().refresh()
            }
        }
        return {
            executeWhenAvailable: executeWhenAvailable,
            isAvailable: isAvailable,
            configurePubAds: configurePubAds,
            clearTargeting: clearTargeting,
            setTargeting: setTargeting,
            setLocation: setLocation,
            setCategoryExclusion: setCategoryExclusion,
            updateCorrelator: updateCorrelator,
            defineOutOfPageSlot: defineOutOfPageSlot,
            defineSlot: defineSlot,
            setSlotCategoryExclusion: setSlotCategoryExclusion,
            setSlotTargeting: setSlotTargeting,
            displaySlotById: displaySlotById,
            defineSlotSizeMapping: defineSlotSizeMapping,
            refreshSlots: refreshSlots,
            clearSlots: clearSlots,
            destroySlots: destroySlots,
            clearSlotTargeting: clearSlotTargeting
        }
    }();

    function _displaySlots(slots, options) {
        _logDebug("Sending Request...", slots);
        options = options || {
                sync: false,
                syncSlots: []
            };
        if (_options.maintaincorrelator) {
            options['maintainCorrelator'] = _options.maintaincorrelator;
        }
        var displayedSlots = [];
        Googletag.configurePubAds();
        var __displaySlot = function(slotId) {
            Googletag.executeWhenAvailable("displaying slot", function() {
                Googletag.displaySlotById(slotId)
            })
        };
        for (var i = 0; i < slots.length; i++) {
            var slotId = slots[i].slot_id;
            if (!document.getElementById(slotId)) {
                _logWarn("Can't Find Slot On Page", slotId)
            } else {
                __displaySlot(slotId);
                displayedSlots.push(slots[i])
            }
        }
        var displayedSlotsIds = displayedSlots.map(function(slot) {
            return slot.slot_id
        });

        Googletag.executeWhenAvailable("refreshing slots", function() {
            var slotsToRefresh = [];
            for (var slotId in pageSlots) {
                if(slotId.indexOf('companion') == -1) {
                    if (pageSlots.hasOwnProperty(slotId)) {
                        if ((options.sync && (!options.syncSlots || options.syncSlots.length == 0 || options.syncSlots.indexOf(slotId) >= 0)) || displayedSlotsIds.indexOf(slotId) >= 0) {
                            if(_options.lazyLoad && (!_options.lazyLoadSlots || _options.lazyLoadSlots.length == 0 || _options.lazyLoadSlots.indexOf(slotId) != -1) ){
                                continue;
                            }
                            slotsToRefresh.push(pageSlots[slotId])
                        }
                    }
                }
            }
            if(slotsToRefresh.length > 0){
                Googletag.refreshSlots(slotsToRefresh)
            }
        });

        if (!options.maintainCorrelator) {
            Googletag.executeWhenAvailable("updating correlator", Googletag.updateCorrelator)
        }
        try {
            var event = new CustomEvent("NascarAdRequestComplete", {
                detail: {
                    slots: JSON.parse(JSON.stringify(displayedSlots)),
                    options: options
                }
            });
            document.dispatchEvent(event)
        } catch (error) {
            _logWarn("error dispatching custom Event: NascarAdRequestComplete", error)
        }
        return displayedSlots
    }

    function setBulkTargeting(data) {
        if (data) {
            for (var key in data) {
                if (data.hasOwnProperty(key)) {
                    if (key == "slotTargets") {
                        for (var k in data[key]) {
                            if (data[key].hasOwnProperty(k)) {
                                NascarAd.addSlotLevelTarget(key, k, data[key][k])
                            }
                        }
                    } else {
                        if (key == "adTargets") {
                            for (var k in data[key]) {
                                if (data[key].hasOwnProperty(k)) {
                                    NascarAd.addPageLevelTarget(key, data[key])
                                }
                            }
                        } else {
                            NascarAd.addPageLevelTarget(key, data[key])
                        }
                    }
                }
            }
        }
    }

    function logit(message, object) {
        _logDebug(object, message)
    }

    function queueSingleton(options) {
        _logDebug("Queuing Singleton", options);
        options.size = options.size || [
                [88, 31]
            ];
        options.targets = options.targets || [];
        options.responsive = options.responsive || [];
        var divId = options.divId;
        if (options.inherit && _globalPageAdId) {
            options.adunit = _globalPageAdId
        }
        if (options.adunit.indexOf("/") >= 0) {
            var first = options.adunit.split("/")[0];
            if (parseInt(first) > 0) {
                var arr = options.adunit.split("/");
                arr.splice(0, 1);
                options.adunit = arr.join("/")
            }
        }
        var page = {
            singleton: true,
            slot_id: "page",
            adunit_name: "singleton_" + divId,
            gpt_id: _options.networkId,
            orig_slot_id: divId,
            site: options.adunit.split("/")[0],
            root: options.adunit.split("/")[0].toUpperCase(),
            responsive: [],
            requested: false
        };
        if (_globalPageTargets && options.targets.length > 0) {
            var newTargets = [];
            for (var i = 0; i < options.targets.length; i++) {
                var target = options.targets[i];
                var flag = false;
                for (var j = 0; j < _globalPageTargets.length; j++) {
                    if (_globalPageTargets[j][0] == target[0]) {
                        flag = true
                    }
                }
                if (!flag) {
                    newTargets.push(target)
                }
            }
            options.targets = newTargets
        }
        page.targeting = _globalPageTargets;
        var slot = {
            present: true,
            responsive: options.responsive,
            slot_id: options.divId,
            sizes: options.size,
            targeting: options.targets,
            adunit_id: options.adunit,
            inherit: options.inherit
        };
        var slot = _updateSlotIfNeeded(slot);
        var arr = [page, slot];
        NascarAd.registry.push(arr);
        if (options.dispatch) {
            NascarAd.dispatchQueue({
                slots: [options.divId]
            })
        }
    }

    function processNewRegistry(url) {
        queueRegistry(url, {
            dispatch: true
        })
    }

    function processNewRegistryAjax(url) {
        _ajax({
            url:url,
            withCredentials:false
        }).then(function(error, data, xhr){
            if(error){
                _hendleAjaxError(error,xhr);
            } else {
                _logDebug("AJAX data", data);
                data = _adjustData(data);
                _logDebug("Adjusted AJAX data", data);
                NascarAd.registry.push(data);
                NascarAd.dispatchQueue({
                    dispatch: true
                });
            }
        });
    }

    function reloadAd(id, pageload, updateCorrelator) {
        NascarAd.refresh([id], {
            pageload: pageload,
            interval: 0,
            updateCorrelator: updateCorrelator
        })
    }

    function refreshAd(id, interval, pageload, updateCorrelator) {
        NascarAd.refresh([id], {
            pageload: pageload || false,
            interval: interval || 0,
            updateCorrelator: updateCorrelator || true
        })
    }

    function refreshAds(ids, interval, pageload, updateCorrelator) {
        NascarAd.refresh(ids, {
            pageload: pageload || false,
            interval: interval || 0,
            updateCorrelator: updateCorrelator || true
        })
    }

    function refreshAllAds(interval, pageload, updateCorrelator) {
        var options = {
            pageload: pageload || false,
            interval: interval || 0,
            updateCorrelator: updateCorrelator || true
        };
        NascarAd.refresh([], options);
        return true
    }

    function renderSingleSlot(divId, size, targets, responsive, adunit, delay, inherit, dispatch) {
        if (divId.indexOf("ad_carousel_slide") >= 0) {
            adunit = "NBA/homepage"
        }
        queueSingleton({
            divId: divId,
            size: size,
            targets: targets,
            responsive: responsive,
            adunit: adunit,
            delay: delay,
            inherit: inherit,
            dispatch: (dispatch == undefined ? true : dispatch),
            sync: false,
            syncSlots: []
        })
    }

    function _initGPTListeners() {
        addEvent(document, "NascarAdRequestComplete", function(data) {
            _logDebug("NascarAd Request Complete", {
                requestEvent: data
            })
        });
        addEvent(document, "GPTRenderComplete", function(data) {
            _logDebug("GPT Render Complete", {
                renderEvent: data
            })
        });
        addEvent(document, "GPTSlotBuildComplete", function(data) {
            _logDebug("GPT Slot Build Complete", {
                renderEvent: data
            })
        });
        addEvent(document, "SlotIdChange", function(data) {
            _logDebug("Slot ID Change", {
                idChangeEvent: data
            })
        })
    }

    function init() {
        if (!_isNascarAdInitiated) {
            _isNascarAdInitiated = true;

            var options = _getOptionsFromTag();
            if(options){
                NascarAd.setOptions(options);
            }

            _initLazyLoadHandler();
            _initOnFocusListeners();
            _initGPTRenderCompleteListener();
            _initTestPageTargets();
            _initGPTListeners();
            _initOnDocumentReadyListeners();
            _dispatchQueueOnceReady();
            _loadSlotsData();
            try {
                var event = new CustomEvent("NascarAdCreated", {
                    detail: {
                        NascarAd: window.NascarAd
                    }
                });
                document.dispatchEvent(event)
            } catch (error) {
                _logWarn("error dispatching custom Event: NascarAdCreated", error)
            }
        }
    }

    function getQueuedSlots() {
        return _clone(_slotQueue)
    }

    function getSlotDetails(slotId) {
        var slot;
        for (var i = 0; i < NascarAd.registry.length; i++) {
            var registryEntry = NascarAd.registry[i];
            for (var j = 1; j < registryEntry.length; j++) {
                var s = registryEntry[j];
                if (s.slot_id == slotId) {
                    slot = _clone(s)
                }
            }
        }
        var adUnit;
        var slotTargeting = {};
        var oldSlot = pageSlots[slotId];
        if (oldSlot) {
            adUnit = oldSlot.getAdUnitPath();
            var keys = oldSlot.getTargetingKeys();
            for (var k in keys) {
                var key = keys[k];
                slotTargeting[key] = oldSlot.getTargeting(key)
            }
        }
        return {
            adUnit: adUnit,
            slot: slot,
            slotTargeting: slotTargeting
        }
    }

    function registerModule(name, callbacks) {
        _logDebug("registering module: " + name);
        var index = -1;
        for (var i = 0; i < _modules.length; i++) {
            if (_modules[i].name == name) {
                index = i
            }
        }
        if (index >= 0) {
            _modules[index].callbacks = callbacks
        } else {
            _modules.push({
                name: name,
                callbacks: callbacks
            })
        }
    }

    function unregisterModule(name) {
        var index = -1;
        for (var i = 0; i < _modules.length; i++) {
            if (_modules[i].name == name) {
                index = i
            }
        }
        if (index >= 0) {
            _modules.splice(index, 1)
        }
    }

    function applyIfReadyWrapper(callback) {
        var callee = arguments.callee;
        var caller = "window/console";
        try {
            caller = callee.caller.toString()
        } catch (error) {
            caller = "window/console"
        }
        return function () {
            if (!_isNascarAdInitiated) {
                _logError("ERROR: NascarAd must be initialized first!");
                _logDebug("------------------FUNCTION --------------------", callback, "--------------- END FUNCTION ------------------", "called by: " + caller);
                return
            } else {
                callback.apply(this, arguments)
            }
        }
    }

    function setOptions(options) {
        if (options) {
            if (options.exclude && options.exclude.length > 0) {
                for (var i = 0; i < options.exclude.length; i++) {
                    var e = options.exclude[i];
                    if (_excludes.indexOf(e) < 0) {
                        _excludes.push(e)
                    }
                }
            }
            for (var key in options) {
                if (options.hasOwnProperty(key)) {
                    _options[key] = options[key]
                }
            }
        }
    }

    function _getOptionsFromTag(){
        var scripts = document.getElementsByTagName('script'),
            script;

        for (var i = scripts.length - 1; i >= 0; --i) {
            if (scripts[i].src.indexOf("nascarDFPAd.js") !== -1) {
                script = scripts[i];
                break;
            }
        }

        if(script){
            var options = {};

            if(script.dataset.lazyload || script.getAttribute("lazyload")){
                if(script.dataset.lazyload){
                    options['lazyLoad'] = (script.dataset.lazyload === 'true');
                } else {
                    options['lazyLoad'] = (script.getAttribute("lazyload") === 'true');
                }
            }
            if(script.dataset.lazyloadslots || script.getAttribute("lazyloadslots")){
                if(script.dataset.lazyloadslots){
                    options['lazyLoadSlots'] = script.dataset.lazyloadslots.split(",");
                } else {
                    options['lazyLoadSlots'] = script.getAttribute("lazyloadslots").split(",");
                }
            }

            try{
                if(script.getAttribute("lazyloadstartdate")){
                    var lazyloadstartdate = new Date( parseInt( script.getAttribute("lazyloadstartdate") ) );
                }
            } catch (e){}
            try{
                if(script.getAttribute("lazyloadenddate")){
                    var lazyloadenddate = new Date( parseInt( script.getAttribute("lazyloadenddate") ) );
                }
            } catch (e){}
            var now = new Date();
            lazyloadstartdate = lazyloadstartdate ? lazyloadstartdate : new Date(now.getTime() - 3600*24*1000);
            lazyloadenddate = lazyloadenddate ? lazyloadenddate : new Date(now.getTime() + 3600*24*1000);

            options['maintaincorrelator'] = options['lazyLoad'] = options['lazyLoad'] && (lazyloadstartdate <  now && now < lazyloadenddate);

            if(script.getAttribute("maintaincorrelator")){
                options['maintaincorrelator'] = (script.getAttribute("maintaincorrelator") === 'true');
            }

            if(script.dataset.refreshonfocusonly || script.getAttribute("refreshonfocusonly")){
                if(script.dataset.lazyload){
                    options['refreshOnFocusOnly'] = (script.dataset.refreshonfocusonly === 'true');
                } else {
                    options['refreshOnFocusOnly'] = (script.getAttribute("refreshonfocusonly") === 'true');
                }
            }
            if(script.dataset.networkId || script.getAttribute("networkId")){
                if(script.dataset.networkId){
                    options['networkId'] = script.dataset.networkId;
                } else {
                    options['networkId'] = script.getAttribute("networkId");
                }
            }
            if(script.getAttribute("autoDispatch")) {
                options['autoDispatch'] = (script.getAttribute("autoDispatch") === 'true');
            }
            if(script.getAttribute("exclude")) {
                options['exclude'] = JSON.parse(script.getAttribute("exclude").replace(/\'/ig, "\""));
            }
            if(script.getAttribute("queueCallbackTimeoutInMilliseconds")) {
                try {
                    options['queueCallbackTimeoutInMilliseconds'] = parseInt(script.getAttribute("queueCallbackTimeoutInMilliseconds"));
                } catch(e){
                    _logError("queueCallbackTimeoutInMilliseconds attribute should be Integer.", e)
                }
            }
            if(script.getAttribute("dispatchCallbackTimeoutInMilliseconds")) {
                try {
                    options['dispatchCallbackTimeoutInMilliseconds'] = parseInt(script.getAttribute("dispatchCallbackTimeoutInMilliseconds"));
                } catch(e){
                    _logError("dispatchCallbackTimeoutInMilliseconds attribute should be Integer.", e)
                }
            }
            if(script.getAttribute("refreshCallbackTimeoutInMilliseconds")) {
                try {
                    options['refreshCallbackTimeoutInMilliseconds'] = parseInt(script.getAttribute("refreshCallbackTimeoutInMilliseconds"));
                } catch(e){
                    _logError("refreshCallbackTimeoutInMilliseconds attribute should be Integer.", e)
                }
            }
            return options;
        }

        return null;
    }

    function _isElementInViewport (el) {
        var rect, result, flag;

        if(el.style.display === 'none'){
            flag = true;
            el.style.display = "";
        }

        rect = el.getBoundingClientRect();

        result = (
        rect.bottom >= 0 &&
        rect.right >= 0 &&
        rect.top <= (window.innerHeight || document.documentElement.clientHeight) &&
        rect.left <= (window.innerWidth || document.documentElement.clientWidth));

        if(flag){
            el.style.display = "none";
        }

        return result
    }

    var _debounce = function(func, wait) {
        var timeout;
        return function() {
            var context = this, args = arguments;
            var later = function() {
                timeout = null;
                func.apply(context, args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    };

    function _lazyLoadHandler(){
        var el, slotsToRefresh=[];

        for (var slotId in pageSlots) {
            if(slotId.indexOf('companion') == -1) {
                if (pageSlots.hasOwnProperty(slotId)) {
                    el = document.getElementById(slotId);
                    if( el &&
                        (!el.className || el.className.indexOf('nascarad-rendered') == -1) &&
                        (!_options.lazyLoadSlots || _options.lazyLoadSlots.length == 0 ||  _options.lazyLoadSlots.indexOf(slotId) != -1 ) &&
                        !pageSlots[slotId]["lazyLoadRendered"] &&
                        _isElementInViewport(el)){
                        pageSlots[slotId]["lazyLoadRendered"] = true;
                        slotsToRefresh.push(pageSlots[slotId]);
                    }
                }
            }
        }
        _logDebug("_lazyLoadHandler",slotsToRefresh);
        if(slotsToRefresh.length > 0){
            Googletag.refreshSlots(slotsToRefresh, false);
        }

    }

    return ({
        _logDebug: _logDebug,
        _logError: _logError,
        init: init,
        logit: logit,
        addEvent: addEvent,
        setOptions: setOptions,
        clearSlot: applyIfReadyWrapper(clearSlot),
        clearSlots: applyIfReadyWrapper(clearSlot),
        destroySlot:applyIfReadyWrapper(destroySlot),
        destroySlots:applyIfReadyWrapper(destroySlot),
        clearAllSlots: applyIfReadyWrapper(clearSlot),
        queueSingleton: queueSingleton,
        processNewRegistry: processNewRegistry,
        processNewRegistryAjax: processNewRegistryAjax,
        reloadAd: applyIfReadyWrapper(reloadAd),
        refreshAd: applyIfReadyWrapper(refreshAd),
        refreshAds: applyIfReadyWrapper(refreshAds),
        refreshAllAds: applyIfReadyWrapper(refreshAllAds),
        renderSingleSlot: renderSingleSlot,
        requestAndRenderAds: requestAndRenderAds,
        pageSlots: pageSlots,
        pageSlotsObj: pageSlots,
        setBulkTargeting: setBulkTargeting,
        dispatchQueue: requestAndRenderAds,
        queueRegistry: queueRegistry,
        queueRegistryAjax: queueRegistryAjax,
        buildSlotsAjax:buildSlotsAjax,
        getQueuedSlots: getQueuedSlots,
        getSlotDetails: getSlotDetails,
        refresh: applyIfReadyWrapper(refresh),
        removePageLevelTarget: applyIfReadyWrapper(removePageLevelTarget),
        removeSlotLevelTarget: applyIfReadyWrapper(removeSlotLevelTarget),
        addPageLevelTarget: applyIfReadyWrapper(addPageLevelTarget),
        addSlotLevelTarget: applyIfReadyWrapper(addSlotLevelTarget),
        generateSingletonId: generateSingletonId,
        registry: new Registry(),
        requestScriptText: "",
        readCookie: readCookie,
        registerModule: registerModule,
        unregisterModule: unregisterModule,
        createVideoAdTag: createVideoAdTag
    })
})();
window.AMPTManager = window.NascarAd;
window.NascarAd.init();
function setDFPCookie(cname, cvalue, exdays) {
    var d = new Date();
    d.setTime(d.getTime() + (exdays * 24 * 60 * 60 * 1000));
    var expires = "expires="+d.toUTCString();
    document.cookie = cname + "=" + cvalue + ";" + expires + ";path=/";

}
window.NascarAd.video = (function(){

    function onTemplateReady(playerObject){
        try{
            if (playerObject &&  playerObject.ima3) {
                playerObject.ima3.settings.requestMode = "onplay";
                playerObject.ima3.ready(function() {
                    var videoAdTag = NascarAd.createVideoAdTag();
                    this.ima3.settings.serverUrl = videoAdTag;
                    NascarAd._logDebug("Video tag is :", videoAdTag);
                });
            }
        } catch(e){
            NascarAd._logError('Brigthcover error' + e);
        }
    }

    return {
        onTemplateReady: onTemplateReady
    }
})();
window.AMPTManager.video = window.NascarAd.video;
setMoatPrebidData = function(dfpSlotData) {
    try {
        if (window.moatPrebidApi && typeof window.moatPrebidApi.slotDataAvailable === 'function'
           // && window.moatPrebidApi.slotDataAvailable()
        ) {
            if (dfpSlotData) {
                window.moatPrebidApi.setMoatTargetingForSlot(dfpSlotData);
            }
        }
        else {
            if(console){
                console.log('moatPrebidApi is not available yet ');
            }
        }
    }catch(e){
        if(console){
            console.log('Error in Setting Moat Targetting '+ e);
        }
    }
}