var $parties = 4
var $intsize = 8

var in_0 = 0
var in_1 = {
    "key": 0,
    "request": 0,
    "seed": 0
}
var in_2 = {
    "key": 0,
    "request": 0,
    "seed": 0
}
var in_3 = {
    "key": 0,
    "request": 0,
    "seed": 0
}

var out_0 = [{
    key: in_1.key,
    request: in_1.request
}, {
    key: in_2.key,
    request: in_2.request
}, {
    key: in_3.key,
    request: in_3.request
}, {}]
var out_1 = 0
var out_2 = 0
var out_3 = 0

var seed = in_1.seed ^ in_2.seed ^ in_3.seed

for (var i = 0; i < 3; i++) {
    var j = i + (random() % (3 - i))
    var tmp = out_0[i]
    out_0[i] = out_0[j]
    out_0[j] = tmp
}

function random() {
    seed = seed * seed
    seed = seed >> 2
    return seed % 16
}
