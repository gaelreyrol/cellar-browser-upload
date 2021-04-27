const crypto = require('crypto');
const express = require('express');
const dayjs = require('dayjs');

require('dotenv').config();

const port = process.env.PORT || 3000;
const app = express();

app.set('view engine', 'ejs');

function signRaw(key, message) {
    const hash = crypto.createHash('sha256', key)
    
    hash.update(message)
    
    return hash.digest('hex');
}

function signPolicy(date, content) {
    const timestampKey = signRaw(`AWS4${process.env.CELLAR_SECRET_ACCESS_KEY}`, date.format('YYYYMMDD'));
    console.log({ timestampKey });
    const timestampRegion = signRaw(timestampKey, 'us-east-1');
    console.log({ timestampRegion });
    const timestampService = signRaw(timestampRegion, 's3');
    console.log({ timestampService });
    const signingKey = signRaw(timestampService, 'aws4_request');
    console.log({ signingKey });

    const hash = crypto.createHash('sha256', signingKey)
    
    hash.update(content)
    
    return hash.digest('hex');
}

function policyToString(policy) {
    return Buffer.from(JSON.stringify(policy)).toString('base64');
}

app.get('/', function(req, res) {
    const now = dayjs();
    const expirationDate = now.add(1, 'hour');

    const credential = `${process.env.CELLAR_ACCESS_KEY_ID}/${now.format('YYYYMMDD')}/us-east-1/s3/aws4_request`;

    const policy = {
        expiration: expirationDate.format('YYYY-MM-DDTHH:mm:ss.SSS') + 'Z',
        conditions: [
            ["starts-with", "$key", ""],
            {"bucket": process.env.CELLAR_BUCKET},
            {"x-amz-algorithm": "AWS4-HMAC-SHA256"},
            {"x-amz-credential": credential},
            {"x-amz-date": now.format('YYYYMMDDTHHmmss') + 'Z'},
        ]
    };

    const signature = signPolicy(now, policyToString(policy));

    res.render('index', {
        form: {
            endpoint: `https://${process.env.CELLAR_BUCKET}.${process.env.CELLAR_HOST}`,
            policy: policyToString(policy),
            date: now.format('YYYYMMDDTHHmmss') + 'Z',
            credential,
            signature
        }
    });
});

app.listen(port, () => {
    console.log(`App listening at http://localhost:${port}`);
});