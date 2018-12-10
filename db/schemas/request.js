let mongoose = require('mongoose')
    , Schema = mongoose.Schema;
let requestSchema = new Schema({
    _id: String,
    code: String,
    request_id: {
        type: String,
        index: true
    },
    request_secret: String,
    request_callback: String,
    request_ip: String,
    viaGateway: Boolean,
    username: {
        type: String,
        index: true
    },
    uuid: String,
    token: String,
    status: {
        type: String,
        enum: ["STARTED", "REQUESTED", "TIMEOUT_LOGIN", "INVALID_TOKEN", "VERIFIED", "NOT_VERIFIED"]
    },
    created: {
        type: Date,
        expires: 600 // 10 minutes
    }
}, {collection: "requests"});
module.exports = {
    schema: requestSchema,
    model: mongoose.model("Request", requestSchema)
};
