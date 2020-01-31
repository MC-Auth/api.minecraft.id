const util = require("../util");
const crypto = require("crypto-js");
const {authStart, authStatus} = require("./authFunctions");
const Request = require("../db/schemas/request").model;
const AuthLog = require("../db/schemas/authlog").model;

module.exports = function (express, config) {
    let router = express.Router();

    // 1. Request (API)
    router.post("/start", function (req, res) {
        let requestId = req.body.request_id;// public
        let secret = req.body.request_secret;// secret
        let callback = req.body.request_callback;// secret
        let ip = req.body.request_ip;// public
        let username = req.body.username;// public

        authStart(requestId, secret, callback, ip, username, false).catch((err) => {
            res.status(err.code).json(err);
        }).then((result) => {
            res.json(result);
        })

    });

    // 2. Request (redirect)
    router.get("/authorize/:id", function (req, res) {
        let id = req.params.id;
        let requestId = req.query.request_id;
        let username = req.query.username;
        let style = req.query.style || "default";
        let ip = req.query.ip;

        Request.findOne({_id: id}).exec(function (err, request) {
            if (!request) {
                res.status(404).json({error: "Request not found"})
                return;
            }

            if (request.request_id !== requestId) {
                res.status(400).json({error: "Request ID mismatch"})
                return;
            }

            if (request.username !== username) {
                res.status(400).json({error: "Username mismatch"})
                return;
            }

            let expires = new Date(Date.now() + 600000);
            res.cookie("mcauth_id", util.base64encode(request._id), {expires: expires, domain: ".minecraft.id", path: "/", secure: true});
            res.cookie("mcauth_request_id", util.base64encode(request.request_id), {expires: expires, domain: ".minecraft.id", path: "/", secure: true});
            res.cookie("mcauth_username", util.base64encode(request.username), {expires: expires, domain: ".minecraft.id", path: "/", secure: true});
            res.cookie("mcauth_style", style, {expires: expires, domain: ".minecraft.id", path: "/", secure: true});

            req.session.auth_id = request._id;
            req.session.auth_request_id = request.request_id;
            req.session.auth_username = request.username;
            req.session.auth_style = style;

            request.status = "REQUESTED";
            request.save(function (err) {
                if (err) return console.error(err);

                AuthLog.update({_id: request._id}, {$set: {"time.authorize": new Date(), status: "REQUESTED"}}, function (err) {
                    res.redirect("https://minecraft.id/#/auth");
                })
            })
        })
    });

    router.get("/api/check/:id", function (req, res) {
        let id = req.params.id;
        Request.findOne({_id: id}).exec(function (err, request) {
            if (!request) {
                res.status(404).json({error: "Request not found"});
                return;
            }

            if (request._id !== req.session.auth_id) {
                res.status(400).json({error: "Session ID mismatch"})
                return;
            }
            if (request.request_id !== req.session.auth_request_id) {
                res.status(400).json({error: "Session Request ID mismatch"})
                return;
            }
            if (request.username !== req.session.auth_username) {
                res.status(400).json({error: "Session Username mismatch"})
                return;
            }

            function done(request) {
                res.json({
                    id: request._id,
                    status: request.status,
                    created: request.created.getTime()
                })
            }

            if ((Date.now() - request.created.getTime()) > 300000) {
                request.status = "TIMEOUT_LOGIN";
                request.save(function (err) {
                    if (err) return console.error(err);
                    done(request);
                })
            } else {
                done(request);
            }
        })
    });

    router.get("/api/verify/:id", function (req, res) {
        let id = req.params.id;
        let token = req.query.token;

        Request.findOne({_id: id}, function (err, request) {
            if (err) return console.error(err);
            if (!request) {
                res.status(404).json({error: "Request not found"})
                return;
            }

            if (request._id !== req.session.auth_id) {
                res.status(400).json({error: "Session ID mismatch"})
                return;
            }
            if (request.request_id !== req.session.auth_request_id) {
                res.status(400).json({error: "Session Request ID mismatch"})
                return;
            }
            if (request.username !== req.session.auth_username) {
                res.status(400).json({error: "Session Username mismatch"})
                return;
            }

            if (!request.token || request.token !== token) {
                request.status = "INVALID_TOKEN";
                request.save(function (err) {
                    if (err) return console.error(err);

                    AuthLog.update({_id: request._id}, {$set: {"time.verify": new Date(), "status": "INVALID_TOKEN"}}, function (err) {
                        if (err) return console.error(err);

                        res.json({
                            id: request._id,
                            status: "INVALID_TOKEN"
                        })
                    })
                })
            } else {
                request.status = "VERIFIED";
                request.save(function (err) {
                    if (err) return console.error(err);

                    AuthLog.update({_id: request._id}, {$set: {"time.verify": new Date(), "status": "VERIFIED"}}, function (err) {
                        if (err) return console.error(err);

                        res.json({
                            id: request._id,
                            status: "VERIFIED"
                        })
                    })
                })
            }
        })
    });

    router.get("/finish/:id", function (req, res) {
        let id = req.params.id;

        Request.findOne({_id: id}, function (err, request) {
            if (err) return console.error(err);
            if (!request) {
                res.status(404).json({error: "Request not found"})
                return;
            }

            if (request._id !== req.session.auth_id) {
                res.status(400).json({error: "Session ID mismatch"})
                return;
            }
            if (request.request_id !== req.session.auth_request_id) {
                res.status(400).json({error: "Session Request ID mismatch"})
                return;
            }
            if (request.username !== req.session.auth_username) {
                res.status(400).json({error: "Session Username mismatch"})
                return;
            }

            let style = req.cookies.mcauth_style || "default";

            let expires = new Date();// expire immediately
            res.cookie("mcauth_id", "", {expires: expires, domain: ".minecraft.id", path: "/", secure: true});
            res.cookie("mcauth_request_id", "", {expires: expires, domain: ".minecraft.id", path: "/", secure: true});
            res.cookie("mcauth_username", "", {expires: expires, domain: ".minecraft.id", path: "/", secure: true});
            res.cookie("mcauth_style", "", {expires: expires, domain: ".minecraft.id", path: "/", secure: true});
            req.session.destroy();

            AuthLog.update({_id: request._id}, {$set: {"time.finish": new Date()}}, function (err) {
                if (err) return console.error(err);

                if (request.viaGateway) {
                    res.redirect("/gateway/__callback?id=" + request._id + "&rid=" + request.request_id + "&c=" + request.code + "&u=" + request.username);
                } else {
                    let redirectUrl = request.request_callback + "?id=" + request._id + "&request_id=" + request.request_id + "&code=" + request.code;
                    if (style === "simple") {
                        res.set('Content-Type', 'text/html');
                        res.send("You should be redirected automatically. If not, <a href='" + redirectUrl + "'>click here</a>.\n" +
                            "<script>window.location = '" + redirectUrl + "';</script>")
                    } else {
                        res.redirect(redirectUrl);
                    }
                }
            })
        });
    });

    router.post("/status/:id", function (req, res) {
        let id = req.params.id;
        let requestId = req.body.request_id;
        let requestSecret = req.body.request_secret;
        let code = req.body.code;

        if (requestId && requestId.startsWith("mca")) {
            res.status(403).end();
            return;
        }

        authStatus(id, requestId, requestSecret, code, false).catch((err) => {
            res.status(err.code).json(err);
        }).then((result) => {
            res.json(result);
        });

    });

    return router;
};
