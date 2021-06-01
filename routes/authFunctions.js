const util = require("../util");
const crypto = require("crypto-js");
const Request = require("../db/schemas/request").model;
const AuthLog = require("../db/schemas/authlog").model;

function authStart(requestId, secret, callback, ip, username, gateway) {
    return new Promise((resolve, reject) => {
        if (!requestId) {
            reject({
                code: 400,
                error: "Missing request ID"
            });
            return;
        }
        if (!secret) {
            reject({
                code: 400,
                error: "Missing request Secret"
            });
            return;
        }
        if (!username) {
            reject({
                code: 400,
                error: "Missing username"
            });
            return;
        }

        Request.find({request_id: requestId}).exec(function (err, existing) {
            if (existing && existing.length > 0) {
                reject({
                    code: 400,
                    error: "Request with this ID already exists"
                });
                return;
            }

            Request.find({username: username, request_ip: ip, status: {'$in': ["STARTED", "REQUESTED"]}}).lean().exec(function (err, existing) {
                if (existing && existing.length > 0) {
                    reject({
                        code: 400,
                        error: "Request with this IP <-> Username combination already exists"
                    });
                    return;
                }

                util.checkUsername(username).catch(() => {
                    reject({
                        code: 400,
                        error: "Invalid username"
                    });
                }).then((uuid) => {
                    uuid = uuid.replace(/-/g, '');
                    let id = String(crypto.SHA1(Date.now() + "" + ip + "" + Math.random() + "" + requestId + "" + Math.random()));
                    let code = String(crypto.SHA256(Date.now() + "" + requestId + "" + Math.random() + "" + ip + "" + Math.random() + "" + username + "" + Math.random() + "" + secret));

                    let request = new Request({
                        _id: id,
                        code: code,
                        request_id: requestId,
                        request_secret: secret,
                        request_callback: callback,
                        request_ip: ip,
                        viaGateway: gateway,
                        username: username,
                        uuid: uuid,
                        status: "STARTED",
                        created: new Date()
                    });
                    request.save(function (err) {
                        if (err) return console.error(err);

                        let log = new AuthLog({
                            _id: id,
                            time: {
                                start: new Date(),
                                authorize: null,
                                verify: null,
                                finish: null,
                                statusCheck: null
                            },
                            username: username,
                            request_id: id,
                            status: "STARTED"
                        });
                        log.save(function (err) {
                            if (err) return console.error(err);

                            resolve({
                                msg: "Authentication requested",
                                id: id,
                                code: code,
                                request_id: requestId,
                                username: username,
                                uuid: uuid,
                                ip: ip,
                                status: "STARTED"
                            })
                        })
                    })

                })
            });
        });
    })
}

function authStatus(id, requestId, requestSecret, code, gateway) {
    return new Promise((resolve, reject) => {
        Request.findOne({_id: id}, function (err, request) {
            if (err) return console.error(err);
            if (!request) {
                reject({
                    code: 400,
                    error: "Request not found"
                });
                return;
            }

            if (request.request_id !== requestId) {
                reject({
                    code: 400,
                    error: "Request ID mismatch"
                });
                return;
            }
            if (request.request_secret !== requestSecret) {
                reject({
                    code: 400,
                    error: "Request Secret mismatch"
                });
                return;
            }
            if (request.code !== code) {
                reject({
                    code: 400,
                    error: "Code mismatch"
                });
                return;
            }

            if (request.viaGateway !== gateway) {
                reject({
                    code: 403,
                    error: "Gateway mismatch"
                });
                return;
            }

            AuthLog.updateOne({_id: request._id}, {$set: {"time.statusCheck": new Date()}}, function (err) {
                if (err) return console.error(err);

                let r = {
                    id: request._id,
                    request_id: request.request_id,
                    username: request.username,
                    uuid: request.uuid,
                    status: request.status === "VERIFIED" ? "VERIFIED" : "NOT_VERIFIED",
                    fail_reason: request.status === "VERIFIED" ? "" : request.status
                };
                if (gateway) {
                    r["callback"] = request.request_callback;
                }
                resolve(r);
            });
        });
    })
}


module.exports = {authStart, authStatus}
