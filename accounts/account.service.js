const config = require('config.json');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require("crypto");
const sendEmail = require('_helpers/send-email');
const db = require('_helpers/db');
const Role = require('_helpers/role');
const FlowApi = require("flowcl-node-api-client");
const config = require("./config.json");

module.exports = {
    authenticate,
    refreshToken,
    revokeToken,
    register,
    verifyEmail,
    forgotPassword,
    validateResetToken,
    resetPassword,
    getAll,
    getById,
    create,
    update,
    delete: _delete
};

async function authenticate({ email, password, ipAddress }) {
    const account = await db.Account.findOne({ email });

    if (!account || !account.isVerified || !bcrypt.compareSync(password, account.passwordHash)) {
        throw 'Email or password is incorrect';
    }

    // authentication successful so generate jwt and refresh tokens
    const jwtToken = generateJwtToken(account);
    const refreshToken = generateRefreshToken(account, ipAddress);

    // save refresh token
    await refreshToken.save();

    // return basic details and tokens
    return {
        ...basicDetails(account),
        jwtToken,
        refreshToken: refreshToken.token
    };
}

async function refreshToken({ token, ipAddress }) {
    const refreshToken = await getRefreshToken(token);
    const { account } = refreshToken;

    // replace old refresh token with a new one and save
    const newRefreshToken = generateRefreshToken(account, ipAddress);
    refreshToken.revoked = Date.now();
    refreshToken.revokedByIp = ipAddress;
    refreshToken.replacedByToken = newRefreshToken.token;
    await refreshToken.save();
    await newRefreshToken.save();

    // generate new jwt
    const jwtToken = generateJwtToken(account);

    // return basic details and tokens
    return {
        ...basicDetails(account),
        jwtToken,
        refreshToken: newRefreshToken.token
    };
}

async function revokeToken({ token, ipAddress }) {
    const refreshToken = await getRefreshToken(token);

    // revoke token and save
    refreshToken.revoked = Date.now();
    refreshToken.revokedByIp = ipAddress;
    await refreshToken.save();
}



async function register(params, origin) {
    // Validar si el usuario existe
    if (await db.Account.findOne({ email: params.email })) {
        // Enviar correo de que el usuario ya existe en el sistema
        return await sendAlreadyRegisteredEmail(params.email, origin);
    }

    // Crear el objeto account
    const account = new db.Account(params);

    // La primera persona que se registra queda con el rol de administrador
    const isFirstAccount = (await db.Account.countDocuments({})) === 0;
    account.role = isFirstAccount ? Role.Admin : Role.User;
    account.verificationToken = randomTokenString();

    // hasheamos la password
    account.passwordHash = hash(params.password);

    // Guardamos la cuenta
    await account.save();

    // Enviamos email
    await sendVerificationEmail(account, origin);
}

async function verifyEmail({ token }) {
    const account = await db.Account.findOne({ verificationToken: token });

    if (!account) throw 'Verificacion fallida';

    account.verified = Date.now();
    account.verificationToken = undefined;
    await account.save();
}

async function forgotPassword({ email }, origin) {
    const account = await db.Account.findOne({ email });

    // Siempre devuelve un ok para prevenir la numeracion de correos
    if (!account) return;

    // Creamos el reseteo de un token que expira despues de 24 hrs
    account.resetToken = {
        token: randomTokenString(),
        expires: new Date(Date.now() + 24 * 60 * 60 * 1000)
    };
    await account.save();

    // Enviamos el correo
    await sendPasswordResetEmail(account, origin);
}

async function validateResetToken({ token }) {
    const account = await db.Account.findOne({
        'resetToken.token': token,
        'resetToken.expires': { $gt: Date.now() }
    });

    if (!account) throw 'Token Invalido';
}

async function resetPassword({ token, password }) {
    const account = await db.Account.findOne({
        'resetToken.token': token,
        'resetToken.expires': { $gt: Date.now() }
    });

    if (!account) throw 'Token Invalido';

    // Actualizamos la contraseña y removemos el reset token
    account.passwordHash = hash(password);
    account.passwordReset = Date.now();
    account.resetToken = undefined;
    await account.save();
}

async function getAll() {
    const accounts = await db.Account.find();
    return accounts.map(x => basicDetails(x));
}

async function getById(id) {
    const account = await getAccount(id);
    return basicDetails(account);
}

async function create(params) {
    // Validamos si existe el correo
    if (await db.Account.findOne({ email: params.email })) {
        throw 'Email "' + params.email + '" Ya esta registrado';
    }

    const account = new db.Account(params);
    account.verified = Date.now();

    // Encriptamos la contraseña
    account.passwordHash = hash(params.password);

    // Guardar cuenta
    await account.save();

    return basicDetails(account);
}

async function update(id, params) {
    const account = await getAccount(id);

    // Validamos (Si el email ha sido cambiado)
    if (params.email && account.email !== params.email && await db.Account.findOne({ email: params.email })) {
        throw 'Email "' + params.email + '" Ya esta siendo usado';
    }

    // Encriptamos si es que ha sido ingresada
    if (params.password) {
        params.passwordHash = hash(params.password);
    }

    // copiamos los parametros a la cuenta y Guardamos
    Object.assign(account, params);
    account.updated = Date.now();
    await account.save();

    return basicDetails(account);
}

async function _delete(id) {
    const account = await getAccount(id);
    await account.remove();
}

// Funciones de ayuda

async function getAccount(id) {
    if (!db.isValidId(id)) throw 'Account not found';
    const account = await db.Account.findById(id);
    if (!account) throw 'Account not found';
    return account;
}

async function getRefreshToken(token) {
    const refreshToken = await db.RefreshToken.findOne({ token }).populate('account');
    if (!refreshToken || !refreshToken.isActive) throw 'Token Invalido';
    return refreshToken;
}

function hash(password) {
    return bcrypt.hashSync(password, 10);
}

function generateJwtToken(account) {
    // creamos un token jwt que contenga el id de la cuenta que expire en 15 minutos
    return jwt.sign({ sub: account.id, id: account.id }, config.secret, { expiresIn: '15m' });
}

function generateRefreshToken(account, ipAddress) {
    // Creamos un refresh token que expire en 7 dias
    return new db.RefreshToken({
        account: account.id,
        token: randomTokenString(),
        expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        createdByIp: ipAddress
    });
}

function randomTokenString() {
    return crypto.randomBytes(40).toString('hex');
}

function basicDetails(account) {
    const { id, title, firstName, lastName, email, role, created, updated, isVerified } = account;
    return { id, title, firstName, lastName, email, role, created, updated, isVerified };
}

async function sendVerificationEmail(account, origin) {
    let message;
    if (origin) {
        const verifyUrl = `${origin}/account/verify-email?token=${account.verificationToken}`;
        message = `<p>Porfavor Haz un click en el link de abajo para verificar tu cuenta:</p>
                   <p><a href="${verifyUrl}">${verifyUrl}</a></p>`;
    } else {
        message = `<p>Porfavor usa el codigo de abajo para poder verificar tu cuenta <code>/account/verify-email</code> api route:</p>
                   <p><code>${account.verificationToken}</code></p>`;
    }

    await sendEmail({
        to: account.email,
        subject: 'Verificacion de Cuenta app motivate- Verificar email',
        html: `<h4>Verificar Email</h4>
               <p>Gracias por registrarte!</p>
               ${message}`
    });
}

async function sendAlreadyRegisteredEmail(email, origin) {
    let message;
    if (origin) {
        message = `<p>Si no recuerdas tu contraseña porfavor visita el siguiente enlace: <a href="${origin}/account/forgot-password">forgot password</a> page.</p>`;
    } else {
        message = `<p>Si no recuerdas tu contraseña reseteala con el siguiente codigo:<code>/account/forgot-password</code> api route.</p>`;
    }

    await sendEmail({
        to: email,
        subject: 'Intento de registro con correo ya existente- MotivateApp - El correo ya ha sido registrado',
        html: `<h4>El correo ya se encuentra registrado</h4>
               <p>Tu correo:<strong>${email}</strong> ya se encuentra registrado en nuestra app.</p>
               ${message}`
    });
}

async function sendPasswordResetEmail(account, origin) {
    let message;
    if (origin) {
        const resetUrl = `${origin}/account/reset-password?token=${account.resetToken.token}`;
        message = `<p>Porfavor clickea el link de abajo para resetear tu contraseña, el link sera valido por un dia:</p>
                   <p><a href="${resetUrl}">${resetUrl}</a></p>`;
    } else {
        message = `<p>Utilice el token a continuación para restablecer su contraseña con el<code>/account/reset-password</code> api route:</p>
                   <p><code>${account.resetToken.token}</code></p>`;
    }

    await sendEmail({
        to: account.email,
        subject: 'MotivateApp - Resetea tu contraseña',
        html: `<h4>Resetea tu contraseña</h4>
               ${message}`
    });
}