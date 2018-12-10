let mongoose = require('mongoose')
    , Schema = mongoose.Schema;
let requestSchema = new Schema({
    _id: String,
    code: String,
    request_id: String,
    request_secret: String,
    request_callback: String,
    request_ip: String,
    username: String,
    uuid: String,
    token:String,
    status: {
        type: String,
        enum: ["STARTED", "REQUESTED", "TIMEOUT_LOGIN", "INVALID_TOKEN", "VERIFIED", "NOT_VERIFIED"]
    },
    created: Date
}, {collection: "requests"});
module.exports = {
    schema: requestSchema,
    model: mongoose.model("Request", requestSchema)
};
