let config = {};

config.port = 3012;

config.mongo = {
    user: "",
    pass: "",
    address: "localhost",
    port: 27017,
    database: "mcauth"
};

config.sessionSecret = "keyboard cat";
config.cookieSecret = "mouse mouse";


module.exports = config;