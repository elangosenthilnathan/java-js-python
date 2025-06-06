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
  try {
    // Generate cryptographically secure random values for IV and salt
    const iv = crypto.randomBytes(16);
    const salt = crypto.randomBytes(16); // Improved: Using random salt instead of hardcoded value
    
    // Use environment variable or secret management service instead of hardcoded key
    const encryptionKey = process.env.ENCRYPTION_KEY || throw new Error('Encryption key not configured');
    
    // Improved: Added cost parameters to scrypt for better security
    const key = crypto.scryptSync(encryptionKey, salt.toString('hex'), 32, {
      N: 16384, // CPU/memory cost parameter
      r: 8,     // Block size parameter
      p: 1      // Parallelization parameter
    });
    
    // Replace weak DES with AES-256-GCM for strong authenticated encryption
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    let encrypted = cipher.update(secretText, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    // Get authentication tag for verified decryption
    const authTag = cipher.getAuthTag().toString('hex');
    
    // Improved: Added key version for future rotation capability
    const keyVersion = '1';
    
    // Improved: Security - clear sensitive data from memory
    setTimeout(() => {
      key.fill(0); // Zero out the key in memory when done
    }, 0);
    
    // Return all necessary components for secure decryption
    return {
      ciphertext: encrypted,
      iv: iv.toString('hex'),
      salt: salt.toString('hex'),
      authTag: authTag,
      version: keyVersion
    };
  } catch (error) {
    // Improved: Added proper error handling
    console.error('Encryption error occurred');
    // Log safely without exposing sensitive details
    return {
      error: 'ENCRYPTION_FAILED',
      success: false
    };
  }
}


decryptData(encryptedText) {
  try {
    // Input validation
    if (!Buffer.isBuffer(encryptedText) && typeof encryptedText !== 'string') {
      throw new Error("Invalid input type: expected Buffer or string");
    }
    
    const buffer = Buffer.isBuffer(encryptedText) ? encryptedText : Buffer.from(encryptedText, 'base64');
    
    // Extract version byte for key rotation support
    const version = buffer[0];
    // Retrieve encryption key based on version
    const encryptionKey = this.getEncryptionKey(version);
    
    if (!encryptionKey) {
      throw new Error("Unsupported encryption version");
    }
    
    // Extract IV (16 bytes after version byte)
    const iv = buffer.slice(1, 17);
    
    // Extract authentication tag (last 16 bytes)
    const authTag = buffer.slice(-16);
    
    // Extract the actual encrypted content
    const encryptedContent = buffer.slice(17, -16);
    
    // Choose algorithm based on version
    const algorithm = this.getAlgorithm(version);
    
    // Create decipher with the determined algorithm
    const decipher = crypto.createDecipheriv(algorithm, encryptionKey, iv);
    
    // Set authentication tag for verified decryption with constant-time comparison
    decipher.setAuthTag(authTag);
    
    // Decrypt and return the data
    const decrypted = decipher.update(encryptedContent);
    return Buffer.concat([decrypted, decipher.final()]).toString('utf8');
  } catch (error) {
    // Enhanced error handling that doesn't leak sensitive information
    this.logDecryptionFailure(error, { version: buffer?.[0] });
    throw new Error("Decryption failed: data may be corrupted or tampered with");
  }
}

// Helper method to get the appropriate encryption key based on version
getEncryptionKey(version) {
  // Key management system implementation
  const keyInfo = config.keys[version] || config.keys.default;
  
  if (!keyInfo) return null;
  
  if (keyInfo.derived) {
    // Use scrypt for key derivation from password
    const scryptAsync = promisify(crypto.scrypt);
    // Using salt stored in configuration
    return scryptAsync(keyInfo.password, keyInfo.salt, keyInfo.keyLength);
  }
  
  // Return pre-computed key
  return Buffer.from(keyInfo.key, 'hex');
}

// Helper method to determine which algorithm to use based on version
getAlgorithm(version) {
  const algorithmMap = {
    1: 'aes-256-gcm',
    2: 'chacha20-poly1305'
  };
  
  return algorithmMap[version] || 'aes-256-gcm'; // Default to AES
}

// Secure logging of decryption failures
logDecryptionFailure(error, metadata) {
  // Implement secure logging with no sensitive data
  const logEntry = {
    timestamp: new Date().toISOString(),
    event: 'decryption_failure',
    errorType: error.name,
    metadata: {
      version: metadata.version
    }
  };
  
  // Log to secure channel without exposing sensitive details
  console.error(JSON.stringify(logEntry));
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
