let express = require('express');
let app = express();
let http = require('http');
let server = http.Server(app);
let bodyParser = require("body-parser");
let cookieParser = require("cookie-parser");
let session = require("express-session");
let mongoose = require("mongoose");
let Schema = mongoose.Schema;
let path = require("path");
let fs = require("fs");
let config = require("./config");
let port = process.env.PORT || config.port || 3021;

app.use(function (req, res, next) {
    res.header('Access-Control-Allow-Origin', 'https://mcauth.org');
    res.header('Access-Control-Allow-Credentials', 'true');
    if (req.method === 'OPTIONS') {
        res.header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE, PUT");
        res.header("Access-Control-Allow-Headers", "X-Requested-With, Accept, Content-Type, Origin");
        res.header("Access-Control-Request-Headers", "X-Requested-With, Accept, Content-Type, Origin");
        return res.sendStatus(200);
    } else {
        return next();
    }
});

app.use(bodyParser.urlencoded({extended: true}));
app.use(bodyParser.json())

app.use(function (req, res, next) {
    req.realAddress = req.header("x-real-ip") || req.realAddress;
    next();
});

app.use("/.well-known", express.static(".well-known"));


app.use(cookieParser(config.cookieSecret));

app.set('trust proxy', 1) // trust first proxy
app.use(session({
    secret: config.sessionSecret,
    resave: true,
    saveUninitialized: false,
    cookie: {
        // secure:true,
        // domain: ".mcauth.org",
        // path: "/",
        // httpOnly: false
    }
}));

// mongoose.plugin(util.idPlugin);
require("./db/db")(mongoose, config);


app.use("/auth", require("./routes/auth")(express, config));
app.use("/util", require("./routes/util")(express, config));
app.use("/status", require("./routes/status")(express, config));
app.use("/gateway", require("./routes/gateway")(express, config));

function exitHandler(err) {
    if (err) {
        console.log("\n\n\n\n\n\n\n\n");
        console.log(err);
        console.log("\n\n\n");
    }
    process.exit();
}


server.listen(port, function () {
    console.log('listening on *:' + port);
});

process.on("exit", exitHandler);
process.on("SIGINT", exitHandler);
process.on("uncaughtException", exitHandler);
