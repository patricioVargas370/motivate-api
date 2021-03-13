const sendEmail = require('_helpers/send-email');
const db = require('_helpers/db');
const config = require('config.json');
const Role = require('_helpers/role');
const licenseKey = require('licensekey');

const CrearLicencia = async()=>{

var userInfo = {
    company: 'www.funwoo.com',
    street: 'Taipei 101',
    city: 'Taipei',
    state: 'Taiwan',
    zip: '100'
};

const userLicense = {
    info: userInfo,
    prodCode: 'MotMate',
    appVersion: '1.0',
    osType: 'Win'
}
 try {
     const license = await licenseKey.createLicense(userLicense);
   console.log(license);
 } catch (err) {
     console.log(err);
 }

}