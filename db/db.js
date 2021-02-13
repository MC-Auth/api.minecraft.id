module.exports = function (mongoose, config) {

    // Connect to DB
    if (config.mongo.url) {
        console.log("Connecting to mongo...");
        mongoose.connect(config.mongo.url);
    } else {
        console.log("Connecting to mongodb://" + ((config.mongo.user || "admin") + ":*****" + "@" + (config.mongo.address || "localhost") + ":" + (config.mongo.port || 27017) + "/" + (config.mongo.database || "database")))
        mongoose.connect("mongodb://" + ((config.mongo.user || "admin") + ":" + (config.mongo.pass || "admin") + "@" + (config.mongo.address || "localhost") + ":" + (config.mongo.port || 27017) + "/" + (config.mongo.database || "database")));
    }

    mongoose.Promise = Promise;
}
