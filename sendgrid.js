#! /usr/bin/env node

const sgMail = require('@sendgrid/mail');
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const msg = {
    to: 'Shubham.Aswal@unisys.com',
    from: 'Satish.K.M@in.unisys.com',
    subject: 'Build Status for '+ process.env.REPOSITORY,
    text: 'Hello, Your Build has been completed',
    html: '<p>Hello, Your Build has been completed, here are the steps results' + process.env.STEPS_STATUS + '</p>',
};

sgMail
    .send(msg)
    .then(() => console.log('Mail sent successfully'))
    .catch(error => console.error(error.toString()));
