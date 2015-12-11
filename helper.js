'use strict';
var funcs = {};
funcs.thunkify = function (fn) {
    // 返回wrapper函数，wrapper函数不立刻执行fn,而仅仅是保存参数
    return function () {
        var args = Array.prototype.slice.call(arguments);
        var ctx = this;
        // wrapper函数返回一个新函数,caller可以在新函数调用中设置done回调函数
        return function (done) {
            args.push(function () {
                done.apply(null, arguments);
            });
            try {
                fn.apply(ctx, args);
            } catch (err) {
                done(err);
            }
        }
    }
};
// get_return(err, data)
funcs.co_call = function (flow, get_return) {
    var slice = Array.prototype.slice;
    // generator的参数
    var gen = flow.apply(null, slice.call(arguments, 2));
    var next = function (data) {
        // data赋值给yield左值&从yield处执行flow知道下一个yield
        // 返回yield右值& ret.value是个thunk
        var ret;
        try {
            ret = gen.next(data);
        }
        catch (err) {
            get_return(err);
            return;
        }
        if (ret.done) {
            get_return(null, ret.value);
            return;
        }
        
        //返回一组thunk函数?
        if (Array.isArray(ret.value)) {
            var count = ret.value.length;
            // 返回一个二维数组
            var results = [];
            ret.value.forEach(function (item, index) {
                item(function () {
                    count--;
                    results[index] = slice.call(arguments);
                    if (count === 0) {
                        next(results);
                    }
                });
            });
        } else {
            ret.value(function () {
                // 异步回调的所有返回值生成新数组，传给yield左值
                next(slice.call(arguments));
            });
        }
    }
    next();
};

funcs.async_read = function (sock, length, callback) {
	// can read ?
	var buf = sock.read(length);
	if( buf ){
		process.nextTick(function(){
            callback(null, buf);
        });
		return;
	}
	// on read
	sock.once('readable', function internal_cb() {
		buf = sock.read(length);
		if( buf ){
			callback(null, buf);
			return;
		}
		sock.once('readable', internal_cb);
	});
}

module.exports = exports = funcs;
