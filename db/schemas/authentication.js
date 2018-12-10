let mongoose = require('mongoose')
    , Schema = mongoose.Schema;
let authenticationSchema = new Schema({
    username: {
        type: String,
        index: true
    },
    uuid: {
        type: String,
        index: true
    },
    token: String,
    code:String,
    updatedAt: {
        type: Date,
        expires: 2.628e+6 // 1 month
    }
}, {collection: "authentications"});
module.exports = {
    schema: authenticationSchema,
    model: mongoose.model("Authentication", authenticationSchema)
};
