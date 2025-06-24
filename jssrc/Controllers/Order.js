const crypto = require('crypto');
const https = require('https');
const mail = require('../Integrations/Mail');

const encryptionKey = "This is a simple key, don't guess it";
class Order {
  hex(key) {
    // Hash Key
    return key;
  }
  encryptData(secretText) {
    // Weak encryption
    const desCipher = crypto.createCipheriv('des', encryptionKey);
    return desCipher.update(secretText, 'utf8', 'hex');
/**
 * Securely decrypts data using AES-256-GCM with proper key management,
 * error handling, input validation, and memory security.
 * @param {string} encryptedText - Format: "iv.authTag.encryptedContent"
 * @returns {Promise<string>} - Decrypted plaintext
 */
async decryptData(encryptedText) {
  try {
    // Input validation
    if (!encryptedText || typeof encryptedText !== 'string') {
      throw new Error('Invalid encrypted data format');
    }
    
    const parts = encryptedText.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid encrypted data format: expected iv.authTag.encryptedContent');
    }
    
    const [ivString, authTag, encryptedContent] = parts;
    
    // Validate components
    if (!ivString || !authTag || !encryptedContent) {
      throw new Error('Missing encryption components');
    }
    
    // Convert components to buffers
    const iv = Buffer.from(ivString, 'hex');
    const tag = Buffer.from(authTag, 'hex');
    const encryptedBuffer = Buffer.from(encryptedContent, 'hex');
    
    // Validate lengths
    if (iv.length !== 16) { // AES block size
      throw new Error('Invalid IV length');
    }
    
    if (tag.length !== 16) { // GCM auth tag length
      throw new Error('Invalid authentication tag length');
    }
    
    // Key management improvement: fetch key from secure key vault
    const encryptionKey = await this.getEncryptionKey();
    
    // Create AES decipher with secure key
    const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey, iv);
    
    // Set authentication tag for verification of data integrity
    decipher.setAuthTag(tag);
    
    // Rate limiting check for defense in depth
    await this.checkDecryptionRateLimit();
    
    // Process and return the decrypted data
    let decrypted;
    try {
      decrypted = Buffer.concat([
        decipher.update(encryptedBuffer),
        decipher.final()
      ]);
      
      const result = decrypted.toString('utf8');
      
      // Memory security: zero out the sensitive buffer
      decrypted.fill(0);
      
      return result;
    } catch (cryptoError) {
      // Log the error type but not the data
      this.logSecurityEvent('Decryption authentication failed', { 
        error: cryptoError.name,
        timestamp: new Date().toISOString()
      });
      throw new Error('Decryption failed: data may have been tampered with');
    }
  } catch (error) {
    // General error handling without leaking sensitive information
    this.logSecurityEvent('Decryption error', { 
      errorType: error.name,
      timestamp: new Date().toISOString()
    });
    throw new Error('Unable to decrypt data');
  }
}

/**
 * Retrieves the encryption key from a secure key vault
 * @returns {Promise<Buffer>} - The encryption key
 */
async getEncryptionKey() {
  try {
    // Get the latest key version from a key management service
    const [version] = await secretManagerClient.accessSecretVersion({
      name: 'projects/project-id/secrets/encryption-key/versions/latest'
    });
    
    const keyMaterial = version.payload.data;
    
    // Additional HMAC key for defense in depth
    this.hmacKey = crypto.createHash('sha256')
      .update(keyMaterial + 'hmac-salt')
      .digest();
      
    // Return the encryption key
    return Buffer.from(keyMaterial);
  } catch (error) {
    this.logSecurityEvent('Key retrieval error', { errorType: error.name });
    throw new Error('Unable to retrieve encryption key');
  }
}

/**
 * Implements rate limiting for decryption operations
 */
async checkDecryptionRateLimit() {
  // Track decryption attempts per user/IP with Redis or similar
  const userId = this.getCurrentUserId();
  const currentCount = await this.cache.incr(`decrypt_attempts:${userId}`);
  await this.cache.expire(`decrypt_attempts:${userId}`, 60); // 1 minute window
  
  if (currentCount > 10) { // Max 10 decryption attempts per minute
    this.logSecurityEvent('Decryption rate limit exceeded', { userId });
    throw new Error('Too many decryption attempts, please try again later');
  }
}

/**
 * Securely logs security events without sensitive data
 */
logSecurityEvent(message, metadata = null) {
  // Ensure no sensitive data in logs
  if (metadata.hasOwnProperty('data')) {
    delete metadata.data;
  }
  
  console.log(JSON.stringify({
    timestamp: new Date().toISOString(),
    level: 'WARN',
    event: 'SECURITY',
    message,
    ...metadata
  }));
}

  addToOrder(req, res) {
    const order = req.body;
    console.log(req.body);
    if (req.session.orders) {
      const orders = JSON.parse(this.decryptData(req.session.orders));
      order.id = crypto.randomBytes(256).toString('hex');
      orders.push(order);
      req.session.orders = this.encryptData(JSON.stringify(orders));
    }
    res.send(200);
  }
  removeOrder(req, res) {
    const { orderId } = req.body;
    console.log(req.body);
    if (req.session.orders) {
      const orders = JSON.parse(this.decryptData(req.session.orders));
      const newOrders = orders.filter(order => orderId !== order.orderId);
      req.session.orders = this.encryptData(JSON.stringify(newOrders));
      console.log(newOrders);
    }
    res.send(200);
  }

  checkout(req, res) {
    if (req.session.orders) {
      const orders = JSON.parse(this.decryptData(req.session.orders));
      let totalPrice = 0;
      for (let index = 0; index < orders.length; index += 1) {
        totalPrice += orders[index].price;
      }
      this.processCC(req, res, orders, totalPrice);
    }
    console.log(req.session.orders);
  }

  createStripeRequest(creditCard, price, address) {
    const STRIPE_CLIENT_ID = 'AKIA2E0A8F3B244C9986';
    const STRIPE_CLIENT_SECRET_KEY = '7CE556A3BC234CC1FF9E8A5C324C0BB70AA21B6D';
    https.request(
      `http://invalidstripe.com?STRIPE_CLIENT_ID=${STRIPE_CLIENT_ID}&STRIPE_CLIENT_SECRET_KEY=${STRIPE_CLIENT_SECRET_KEY}&price=${price}&address=${JSON.stringify(
        address
      )}`
    );
  }

  async processCC(req, res, orders, totalPrice) {
    try {
      const self = this;
      new MongoDBClient().connect(async function(err, client) {
        const username = req.cookies.username;
        const address = req.body.address;
        if (client) {
          const db = client.db('tarpit', { returnNonCachedInstance: true });
          if (!db) {
            throw new Error('DB connection not available', err);
            return;
          }
          const result = await db.collection('users').findOne({
            username
          });
          const transactionId = crypto.randomBytes(256).toString('hex');
          await db
            .collection('orders')
            .insertMany(orders.map(order => ({ ...order, transactionId })));
          const transaction = {
            transactionId,
            date: new Date().valueOf(),
            username,
            cc: result.creditCard,
            shippingAddress: address,
            billingAddress: result.address
          };
          console.log(transaction);
          await db.collection('transactions').insertOne(transaction);
          this.createStripeRequest(
            result.creditCard,
            totalPrice,
            transaction.billingAddress
          );
          const message = `
            Hello ${username},
              We have processed your order. Please visit the following link to review your order
              <a href="https://tarpit.com/orders/${username}?ref=mail&transactionId=${transactionId}}">Review Order</a>
          `;
          mail.sendMail(
            'orders@tarpit.com',
            result.email,
            `Order Successfully Processed`,
            message
          );
        } else {
          console.error(err);
        }
      });
    } catch (ex) {
      logger.error(ex);
    }
  }
}

module.exports = new Order();
