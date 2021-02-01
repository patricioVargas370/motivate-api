const FlowApi = require("flowcl-node-api-client");
const config = require("../config.json");

//Para datos opcionales campo "optional" prepara un arreglo JSON
const optional = {
    "rut": "9999999-9",
    "otroDato": "otroDato"
};
//Prepara el arreglo de datos
const params = {
    "commerceOrder": Math.floor(Math.random() * (2000 - 1100 + 1)) + 1100,
    "subject": "Pago de prueba",
    "currency": "CLP",
    "amount": 5000,
    "email": "efuentealba@json.cl",
    "paymentMethod": 9,
    "urlConfirmation": config.misDatos.baseURL + "/payment_confirm",
    "urlReturn": config.misDatos.baseURL + "/result",
    ...optional
};
//Define el metodo a usar
const serviceName = "payment/create";

try {
    // Instancia la clase FlowApi
    const flowApi = new FlowApi(config.misDatos);
    // Ejecuta el servicio
    let response = await flowApi.send(serviceName, params, "POST");
    //Prepara url para redireccionar el browser del pagador
    redirect = response.url + "?token=" + response.token;
    console.log(`location: ${redirect}`)
} catch (error) {
    console.log(error.message)
}