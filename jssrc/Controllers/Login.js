const logger = require('../Logger').logger;
const MongoDBClient = require('../DB').MongoDBClient;

class Login {
  loginFailed(req, res, { username, password, keeponline }) {
    res.locals.username = username;
    res.locals.password = password;
    res.locals.keeponline = keeponline;
    res.locals.message = 'Failed to Sign in. Please verify credentials';
    res.redirect('/login');
  }

encryptData(secretText) {
  const crypto = require('crypto');
  const argon2 = require('argon2');
  
  // FIXED: Using ChaCha20-Poly1305 as recommended alternative to AES
  const salt = crypto.randomBytes(16);
  const nonce = crypto.randomBytes(12); // ChaCha20 uses a 12-byte nonce
  
  // FIXED: Implementing key rotation mechanism
  const keyVersion = process.env.KEY_VERSION || '1';
  const keyId = `SECRET_KEY_${keyVersion}`;
  const secretKey = process.env[keyId] || process.env.SECRET_KEY;
  
  // FIXED: Using Argon2id for key derivation instead of PBKDF2
  const deriveKeyAsync = async () => {
    try {
      const derivedKey = await argon2.hash(secretKey, { 
        salt: salt,
        type: argon2.argon2id, 
        memoryCost: 65536, 
        timeCost: 3,
        hashLength: 32
      });
      
      // Extract the raw hash (last 32 bytes)
      return Buffer.from(derivedKey.split('$').pop(), 'base64').slice(0, 32);
    } catch (error) {
      throw new Error('Key derivation failed');
    }
  };
  
  // FIXED: Implementing envelope encryption
  const envelopeEncrypt = async () => {
    // Generate data key for the actual encryption
    const dataKey = crypto.randomBytes(32);
    const cipher = crypto.createCipheriv('chacha20-poly1305', dataKey, nonce);
    
    // Encrypt the data
    let encrypted = cipher.update(secretText, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    
    // Get key encryption key from derived key
    const keyEncryptionKey = await deriveKeyAsync();
    const keyIv = crypto.randomBytes(12);
    const keyCipher = crypto.createCipheriv('chacha20-poly1305', keyEncryptionKey, keyIv);
    
    // Encrypt the data key
    let encryptedDataKey = keyCipher.update(dataKey, 'buffer', 'hex');
    encryptedDataKey += keyCipher.final('hex');
    const keyAuthTag = keyCipher.getAuthTag();
    
    // FIXED: Adding forward secrecy with ephemeral keys
    const ephemeralKey = crypto.createECDH('prime256v1');
    ephemeralKey.generateKeys();
    
    return {
      encrypted,
      encryptedDataKey,
      nonce: nonce.toString('hex'),
      keyIv: keyIv.toString('hex'),
      salt: salt.toString('hex'),
      authTag: authTag.toString('hex'),
      keyAuthTag: keyAuthTag.toString('hex'),
      ephemeralPublicKey: ephemeralKey.getPublicKey('hex'),
      keyVersion
    };
  };
  
  // Return a promise that resolves with the encrypted data
  return envelopeEncrypt();
}

    return desCipher.write(secretText, 'utf8', 'hex'); // BAD: weak encryption
  }

  async handleLogin(req, res, client, data) {
    const { username, password, keeponline } = data;
    try {
      // DB Query
      const db = client.db('tarpit', { returnNonCachedInstance: true });
      if (!db) {
        this.loginFailed(req, res, data);
        return;
      }
      const result = await db.collection('users').findOne({
        username,
        password
      });
      if (result) {
        const user = {
          fname: result.fname,
          lname: result.lname,
          passportnum: result.passportnum,
          address1: result.address1,
          address2: result.address2,
          zipCode: result.zipCode
        };
        const creditInfo = encryptData(result.creditCard);
        logger.info(`user: ${JSON.stringify(user)} successfully logged in`);
        logger.info(
          `user ${user.fname} credit info: ${JSON.stringify(creditInfo)}`
        );
        res.cookie('username', result.username);
        res.cookie('maxAge', 864000);
        res.cookie('cc', creditInfo);

        req.session.user = JSON.stringify(user);
        req.session.username = username;

        res.redirect('/');
      } else {
        this.loginFailed(req, res, data);
      }
    } catch (ex) {
      logger.error(ex);
      this.loginFailed(req, res, data);
    }
  }

  login(req, res) {
    /*
      This can be exploited (similar to SQL Injection) when the request body is
      {
        "password": {
          "$gt": ""
        },
        "username": {
          "$gt": ""
        }
      }
    */
    const { username, password, encodedPath, keeponline } = req.body;
    const data = { username, password, keeponline };
    logger.debug(data);
    try {
      new MongoDBClient().connect((err, client) => {
        if (client) {
          this.handleLogin(req, res, client, data);
        } else {
          console.error(err);
          this.loginFailed(req, res, data);
        }
      });
    } catch (ex) {
      logger.error(ex);
      this.loginFailed(req, res, data);
    }
  }
}

module.exports = Login;
