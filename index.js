const crypto = require('crypto');
const express = require('express');
const dayjs = require('dayjs');

require('dotenv').config();

const port = process.env.PORT || 3000;
const app = express();

const region = 'us-east-1';

app.set('view engine', 'ejs');

function signRaw(key, message) {   
    return crypto.createHash('sha256', key).update(message).digest();
}

function signPolicy(date, content) {
    const timestampKey = signRaw(`AWS4${process.env.CELLAR_SECRET_ACCESS_KEY}`, date.format('YYYYMMDD'));
    const timestampRegion = signRaw(timestampKey, region);
    const timestampService = signRaw(timestampRegion, 's3');
    const signingKey = signRaw(timestampService, 'aws4_request');
    
    return crypto.createHash('sha256', signingKey).update(content).digest('hex')
}

function policyToString(policy) {
    return Buffer.from(JSON.stringify(policy), 'utf8').toString('base64');
}

app.get('/', function(req, res) {
    const now = dayjs();
    const expirationDate = now.add(4, 'hour');

    const credential = `${process.env.CELLAR_ACCESS_KEY_ID}/${now.format('YYYYMMDD')}/${region}/s3/aws4_request`;

    const policy = {
        expiration: expirationDate.format('YYYY-MM-DDTHH:mm:ss.SSS') + 'Z',
        conditions: [
            ['starts-with', '$key', ''],
            {'bucket': process.env.CELLAR_BUCKET},
            {'x-amz-algorithm': 'AWS4-HMAC-SHA256'},
            {'x-amz-credential': credential},
            {'x-amz-date': now.format('YYYYMMDDTHHmmss') + 'Z'},
        ]
    };

    const signature = signPolicy(now, policyToString(policy));

    res.render('index', {
        form: {
            endpoint: `https://${process.env.CELLAR_BUCKET}.${process.env.CELLAR_HOST}/`,
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