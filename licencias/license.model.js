const mongoose = require('mongoose');
const Schema = mongoose.Schema;


const licenses =new Schema({
    idUsuario:{type:String},
    licencia: {type:String},
    fechaInicio:{type:Date},
    fechaFinal:{type:Date},
});


module.exports = mongoose.model('licenses', licenses);