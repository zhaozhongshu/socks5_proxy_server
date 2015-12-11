'use strict';
var net = require('net');
var dgram = require('dgram');
var util = require('util');
var helper = require('./helper');

var socks = net.createServer({family: 'IPv4'});

var async_read = helper.thunkify(helper.async_read);

var Accounts = [
	{
		user:'user1', 
		pass:'pass1',
	},
	{
		user:'user2',
		pass:'pass2'
	},
	{
		user:'zzs',
		pass:'123'
	},
];

// o  X'00' NO AUTHENTICATION REQUIRED
// o  X'01' GSSAPI
// o  X'02' USERNAME/PASSWORD
// o  X'03' to X'7F' IANA ASSIGNED
// o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
// o  X'FF' NO ACCEPTABLE METHODS
var AUTH_METHOD = {
	NONE: 0,
	GSSAPI: 1,
	USER_PASS: 2,
	DENY: 0xff,
};
// o  CMD
//    o  CONNECT X'01'
//    o  BIND X'02'
//    o  UDP ASSOCIATE X'03'
var CMD = {
	CONNECT: 1,
	BIND: 2,
	UDP_ASSOCIATE: 3
};

// o  ATYP   address type of following address
//    o  IP V4 address: X'01'
//    o  DOMAINNAME: X'03'
//    o  IP V6 address: X'04'
var ATYP = {
	V4: 1,
	DOMAIN: 3,
	V6:4
};
// o  REP    Reply field:
//    o  X'00' succeeded
//    o  X'01' general SOCKS server failure
//    o  X'02' connection not allowed by ruleset
//    o  X'03' Network unreachable
//    o  X'04' Host unreachable
//    o  X'05' Connection refused
//    o  X'06' TTL expired
//    o  X'07' Command not supported
//    o  X'08' Address type not supported
//    o  X'09' to X'FF' unassigned
function* socks_handler(socket) {
   // +----+----------+----------+
   // |VER | NMETHODS | METHODS  |
   // +----+----------+----------+
   // | 1  |    1     | 1 to 255 |
   // +----+----------+----------+
    var ret = yield async_read(socket, 2);
    if( ret[0] ){
        console.log('async_read err:\n'+ret[0].stack);
        socket.end();
    	return;
    }
    ret = ret[1];
    if (ret[0] != 5) {
        console.log('recv bad version:' + ret[0]);
        socket.end();
        return;
    }
    var cMethods = ret[1];
    ret = yield async_read(socket, cMethods);
    if (ret[0]) {
        console.log('async_read err:\n' + ret[0].stack);
        socket.end();
        return;
    }
    // 服务器目前只支持0 2
    var cMethod = Accounts.length == 0 ? AUTH_METHOD.NONE : AUTH_METHOD.USER_PASS;
     // +----+--------+
     // |VER | METHOD |
     // +----+--------+
     // | 1  |   1    |
     // +----+--------+
    // 写入选择的methods
    var buf = new Buffer(2);
    buf[0] = 5;
    buf[1] = cMethod;
    socket.write(buf);

    // 认证客户端账号密码
    if (cMethod == AUTH_METHOD.USER_PASS) {
	 // username/password request looks like
	 // +----+------+----------+------+----------+
	 // |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
	 // +----+------+----------+------+----------+
	 // | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
	 // +----+------+----------+------+----------+
        ret = yield async_read(socket, 2);
        if (ret[0]) {
            console.log('async_read err:\n' + ret[0].stack);
            socket.end();
            return;
        }
        if( ret[1][0] != 1 ){
        	console.log('bad username/pw subnegotiation version ' + ret[1][0]);
            socket.end();
            return;
        }
        ret = yield async_read(socket, ret[1][1]);
        if( ret[0] ){
        	console.log('async_read err:\n' + ret[0].stack);
            socket.end();
            return;
        }
        var userName = ret[1].toString('utf8');

        ret = yield async_read(socket, 1);
        if (ret[0]) {
            console.log('async_read err:\n' + ret[0].stack);
            socket.end();
            return;
        }
        ret = yield async_read(socket, ret[1][1]);
        if( ret[0] ){
        	console.log('async_read err:\n' + ret[0].stack);
            socket.end();
            return;
        }
        var passWord = ret[1].toString('utf8');
        
        console.log('username:' + userName);
        console.log('password:' + passWord);

        var exist = Accounts.some(function (item) {
            return item.user == userName && item.pass == passWord;
        });
        
        // echo username+password validation
        var buf = new Buffer(2);
        if (!exist) {
        	buf[0] = 1;
        	buf[1] = 1;
        	socket.write(buf, function (argument) {
        		socket.end();
        	});
        	return;
        }
        buf[0] = 1;
        buf[1] = 0;
        socket.write(buf);
    }
    // +----+-----+-------+------+----------+----------+
    // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+    
    ret = yield async_read(socket, 4);
    if( ret[0] ){
		console.log('async_read err:\n' + ret[0].stack);
	    socket.end();
	    return;
    }
    ret = ret[1];
    if( ret[0] != 5){
    	console.log('recv bad hostname');
    	socket.end();
    	return;
    }
    var method = ret[1];
    
    var Host;
    if( ret[3] ==ATYP.V4 ){
    	// ipv4
	    ret = yield async_read(socket, 4);
	    if( ret[0] ){
			console.log('async_read err:\n' + ret[0].stack);
		    socket.end();
		    return;
	    }
	    ret = ret[1];
	    Host = ''+ret[0]+'.'+ret[1]+'.'+ret[2]+'.'+ret[3];
    }
    else if( ret[3] == ATYP.DOMAIN ){
    	// domain name
    	ret = yield async_read(socket, 1);
    	if( ret[0] ){
			console.log('async_read err:\n' + ret[0].stack);
		    socket.end();
		    return;
	    }
	    ret = yield async_read(socket, ret[1][0]);
    	if( ret[0] ){
			console.log('async_read err:\n' + ret[0].stack);
		    socket.end();
		    return;
	    }
	    Host = ret[1].toString('utf8');
    }
    else if( ret[3] == ATYP.V6 ){
    	// ipv6
    }
    if( !Host ){
		console.log('read Host failed');
	    socket.end();
	    return;
    }

    // Port
    ret = yield async_read(socket, 2);
    if( ret[0] ){
		console.log('async_read err:\n' + ret[0].stack);
	    socket.end();
	    return;
    }
    var Port = ret[1][0] * 256 + ret[1][1];

    var gen_resp;

    if( method == CMD.CONNECT  ){
    	// connect
    	var ssocket = net.connect({ host: Host, port: Port });
    	
    	socket.on('error', function () {
    		ssocket.end();
    	});

    	ssocket.on('connect', function () {
    		console.log('connect '+ Host + ':' + Port + ' success');
    		
    		var addr = ssocket.address();
    	    var buf = gen_resp(0, addr.address, addr.port);

    	    socket.write(buf, function (err) {
    	        if (!err) {
    	            ssocket.pipe(socket);
    	            socket.pipe(ssocket);
    	        }
    	        else{
    	        	ssocket.end();
    	        }
    	    });
    	});

    	ssocket.on('error', function (err) {
    		console.log('connect '+ Host + ':' + Port + ' ' + err);
    		socket.end();
    	});
    }
    else if( method == CMD.UDP_ASSOCIATE ){
    	// udp associate
        var ssocket = dgram.createSocket('udp4');
        
    	var sip = socket._getsockname().address;
        var sport = null;
        var cip = socket._getpeername().address;
        var cport = Port;

        ssocket.on('listening', function (addr) {
            console.log('udp_associate ' + Host + ':' + Port + ' success');
            
            sport = ssocket.address().port;

		    var buf = gen_resp(0, sip, sport);

		    socket.write(buf, function (err) {
		        if (!err) {
		        }
		        else{
		        	ssocket.end();
		        }
		    });
        });

        ssocket.on('message', function (msg, rinfo) {
	    // +----+------+------+----------+----------+----------+
	    // |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
	    // +----+------+------+----------+----------+----------+
	    // | 2  |  1   |  1   | Variable |    2     | Variable |
	    // +----+------+------+----------+----------+----------+
        	// udp消息转发
        	if( rinfo.address == cip && rinfo.port == cport ){
        		// 发送消息
    			if( msg.length < 10 ){
    				console.log('udp bad length');
    				return;
    			}
    			if( msg[0] != 0 || msg[1] != 0 ){
    				console.log('udp rsv not zero');
    				return;
    			}
    			if( msg[2] != 0 ){// do not support fragment
    				console.log('udp do not support fragment');
    				return;
    			}
    			// 读取Host
    			var offset = 4;
    			var Host;
			    if( msg[3] ==ATYP.V4 ){
			    	// ipv4
				    Host = ''+msg[4]+'.'+msg[5]+'.'+msg[6]+'.'+msg[7];
				    offset += 4;
			    }
			    else if( msg[3] == ATYP.DOMAIN ){
			    	// domain name
			    	var len = msg[4];
			    	if( msg.length < len + 1 + 6 ){
			    		console.log('udp bad length');
    					return;
			    	}
			    	Host = msg.toString('utf8', 5, 5 + len);
			    	offset += 1 + len;
			    }
			    else/* if( ret[3] == ATYP.V6 )*/{
			    	// ipv6
			    	console.log('udp not support');
			    	return;
			    }
			    // 读取Port
			    var Port = msg[offset] * 256 + msg[offset+1];
			    offset+=2;
                ssocket.send(msg, offset, msg.length - offset, Port, Host);
                console.log('send udp to '+ Host + ':' + Port + ' length:' + (msg.length - offset));
        	}
        	else{
        		// 接收消息
        		var nbuf = new Buffer(10 + msg.length);
        		nbuf[0] = 0;
        		nbuf[1] = 0;
        		nbuf[2] = 0;
        		nbuf[3] = ATYP.V4;
        		var tmp = rinfo.address.split('.');
        		nbuf[4] = 0 + tmp[0];
        		nbuf[5] = 0 + tmp[1];
        		nbuf[6] = 0 + tmp[2];
        		nbuf[7] = 0 + tmp[3];
        		nbuf[8] = Port >> 8;
        		nbuf[9] = Port % 0x100;
        		msg.copy(nbuf, 10, 0, msg.length);
                ssocket.send(nbuf, 0, nbuf.length, cport, cip);
                console.log('recv udp from ' + rinfo.address + ':' + rinfo.port + ' length:' + msg.length);
        	}
        });

        ssocket.on('close', function () {
        	console.log('udp close');
        	socket.end();
        });

        ssocket.on('error', function (err) {
        	console.log('udp err ' + err);
        	socket.end();
        });

        ssocket.bind();

        socket.on('error', function () {
    		ssocket.end();
    	});
    }
    else{
    	console.log('bad method');
    	socket.end();
    	return;
    }
    
    // +----+-----+-------+------+----------+----------+
    // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+
    // o  VER    protocol version: X'05'
    gen_resp = function (resp, ip, port) {
    	ip = ip ? ip : '0.0.0.0';
    	port = port ? port : 0;

    	var buf = new Buffer(4 + 6);
    	buf[0] = 5; 	//VER
    	buf[1] = resp; 	//SUCCESS
    	buf[2] = 0; 	//rsv
    	buf[3] = 1;		//IP

    	var Ip = ip.split('.');
    	buf[4] = 0+Ip[0];
    	buf[5] = 0+Ip[1];
    	buf[6] = 0+Ip[2];
    	buf[7] = 0+Ip[3];
    	// Port
    	buf[8] = port >> 8;
    	buf[9] = port % 0x100;
    	return buf;
    }
}

// connection
socks.on('connection', function (socket) {
    // socket.write('socks server\r\n');
    // socket.pipe(socket);
    
    socket.on('end', function () {
        // body...
        console.log('socket end event');
    });
    
    socket.on('timeout', function () {
        console.log('socket timeout event');
    });
    
    socket.on('error', function (err) {
        console.log('socket error ' + err);
    });
    
    socket.on('close', function (err) {
        console.log('socket close event');
    });
    
   	helper.co_call(socks_handler, function (err, data) {
   		if( err ){
            console.log(err.stack);
   		}
   	}, socket);
    // co(socks_handler, socket).then(function (ret) {
    // }, 
    // function (err) {
    //     console.error(err.stack);
    // });
});

socks.on('listening', function () {
	console.log('socks proxy server listening on localhost:' + socks.address().port);
});

socks.on('close', function () {
	// body...
});

socks.on('error', function  (err) {
	console.log('error '+ err);
});
// '0.0.0.0' bind to ipv4
socks.listen(8081, '0.0.0.0');