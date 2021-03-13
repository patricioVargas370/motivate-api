const express = require('express');
const router = express.Router();
const Joi = require('joi');
const validateRequest = require('_middleware/validate-request');
const authorize = require('_middleware/authorize')
const Role = require('_helpers/role');
const licenseService = require('./license.service');

//RUTAS
router.post('/create', CrearSchema,Create);


//FUNCIONES


