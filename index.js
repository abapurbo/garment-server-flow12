require('dotenv').config();
const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const crypto = require('crypto');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const stripe = require('stripe')(process.env.Secret_key);
const admin = require("firebase-admin");

const app = express();
const port = process.env.PORT || 4000;

// Firebase Admin Setup
const decoded = Buffer.from(process.env.FB_SERVICE_KEY, 'base64').toString('utf8');
const serviceAccount = JSON.parse(decoded);
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});

// Middleware
app.use(morgan('dev'));
app.use(express.json());
app.use(cors());

// Generate Order/Tracking ID
function generateTrackingId() {
    const prefix = "ORD"; // Order prefix
    const date = new Date().toISOString().slice(0, 10).replace(/-/g, ""); // YYYYMMDD
    const random = crypto.randomBytes(3).toString("hex").toUpperCase(); // 6-char random
    return `${prefix}-${date}-${random}`;
}

// Firebase Token Verification Middleware
const verifyFBToken = async (req, res, next) => {
    const authorization = req.headers.authorization;
    if (!authorization) return res.status(401).send({ message: "Unauthorized access" });

    const token = authorization.split(" ")[1];
    if (!token) return res.status(401).send({ message: "Unauthorized access" });

    try {
        const decoded = await admin.auth().verifyIdToken(token);
        req.decoded_email = decoded.email;
        next();
    } catch (err) {
        return res.status(401).send({ message: "Unauthorized access" });
    }
};

// MongoDB Setup
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.p9igsxk.mongodb.net/?appName=Cluster0`;
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

// Run server
async function run() {
    try {
        await client.connect();
        const db = client.db('garmentFlowDb');

        const usersCollection = db.collection('users');
        const productCollection = db.collection('allProduct');
        const orderCollection = db.collection('buyerOrder');
        const paymentCollection = db.collection('payment');
        const trackingsCollection = db.collection('trackings');

        // Trackings Logger
        const logTracking = async (trackingId, status, buyerEmail, dateTime, location = 'Main Factory – Gazipur', notes = '') => {
            const log = {
                trackingId,
                status,
                buyerEmail,
                createdAt: dateTime ? new Date(dateTime) : new Date(),
                location,
                notes,
            };
            return await trackingsCollection.insertOne(log);
        };

        // Admin Verify
        const adminVerify = async (req, res, next) => {
            const user = await usersCollection.findOne({ email: req.decoded_email });
            if (!user || user.role !== 'admin') return res.status(403).send({ message: 'forbidden access' });
            next();
        };

        // Manager Verify
        const managerVerify = async (req, res, next) => {
            const user = await usersCollection.findOne({ email: req.decoded_email });
            if (!user || user.role !== 'manager') return res.status(403).send({ message: 'forbidden access' });
            next();
        };

        // Get all users (Admin only)
        app.get('/all-users', verifyFBToken, adminVerify, async (req, res) => {
            try {
                const users = await usersCollection.find({ role: { $ne: "admin" } }).toArray();
                res.send(users);
            } catch (error) {
                console.error(error);
                res.status(500).send({ message: 'Server Error' });
            }
        });


        // Get user role
        app.get('/users/:email/role', verifyFBToken, async (req, res) => {
            try {
                const email = req.params.email;

                // Check if the decoded email from Firebase token matches the requested email
                if (!req.decoded_email || req.decoded_email !== email) {
                    return res.status(403).send({ message: "Forbidden access" });
                }

                // Find the user in the database
                const user = await usersCollection.findOne({ email: email });

                if (!user) {
                    return res.status(404).send({ message: 'User not found' });
                }

                // Send the role and status
                res.send({
                    role: user.role || 'buyer', status: user.status || 'pending', suspendReason: user.suspendReason || '',
                    suspendedAt: user.
                        suspendedAt || ''
                });
            } catch (error) {
                console.error('Error fetching user role:', error);
                res.status(500).send({ message: 'Internal Server Error' });
            }
        });


        // Add User
        app.post('/user', async (req, res) => {
            const { email, role = 'buyer', ...rest } = req.body;
            const existingUser = await usersCollection.findOne({ email });
            if (existingUser) return res.send({ message: 'user already exists' });

            const newUser = { email, role, ...rest, createdAt: new Date(), status: 'pending' };
            console.log(newUser)
            const result = await usersCollection.insertOne(newUser);
            res.send(result);
        });
        // update role / status / suspend reason
        app.patch("/user/update/:email", verifyFBToken, adminVerify, async (req, res) => {
            const email = req.params.email;
            const { role, status, suspendFeedback } = req.body;
            console.log(req.body)
            let updateDoc = {};

            if (status === "suspended" && !suspendFeedback) {
                return res.status(400).send({
                    message: "Suspend reason is required",
                });
            }


            if (role && status) {
                updateDoc = {
                    $set: {
                        role: role,
                        status: status
                    }
                }
            }
            if (status === 'suspended' && suspendFeedback && role) {
                updateDoc = {
                    $set: {
                        role: role,
                        status: status,
                        suspendReason: suspendFeedback,
                        suspendedAt: new Date()
                    },
                }
            }

            if (role && status !== 'suspended') {
                updateDoc = {
                    $set: {
                        role: role,
                        status: status,
                    },
                    $unset: {
                        suspendReason: "",
                        suspendedAt: ""
                    }
                }
            }


            const query = { email: email }
            console.log(query)

            const result = await usersCollection.updateOne(query, updateDoc);

            res.send({
                success: true,
                modifiedCount: result.modifiedCount,
            });
        }
        );

        // all products apis get admin
        app.get('/all-products/admin', verifyFBToken, adminVerify, async (req, res) => {
            const products = await productCollection.find({}).toArray();
            res.send(products);
        })
        // manager all products
        app.get('/manage-products', verifyFBToken, managerVerify, async (req, res) => {
            const email = req.query.email;
            if (req.decoded_email !== email) {
                return res.status(403).send({ message: 'Forbidden access' })
            }
            const result = await productCollection.find({ providerEmail: email }).toArray()
            res.send(result)
        })
        // search products
        app.get('/search-products', verifyFBToken, async (req, res) => {
            const searchText = req.query.searchText || "";
            const query = {
                name: { $regex: searchText, $options: 'i' }
            }
            const result = await productCollection.find(query).toArray();
            res.send(result)

        })


        // Add Product (Manager)
        app.post('/add-product', verifyFBToken, managerVerify, async (req, res) => {
            const product = req.body;
            console.log('skhfks', product);
            const providerEmail = req.decoded_email;
            const newProduct = {
                ...product,
                price: Number(product.price),
                minOrderQty: Number(product.minOrderQty),
                availableQty: Number(product.availableQty),
                providerEmail,
                createdAt: new Date()
            };
            console.log(newProduct);
            const result = await productCollection.insertOne(newProduct);

            res.send(result);
        });


        // Get all products (client)
        app.get('/all-product', async (req, res) => {
            const { limit = 0, skip = 0, sortField = 'price', order = 'desc', search = '' } = req.query;
            const filter = search ? { name: { $regex: search, $options: 'i' } } : {};
            const sortOption = { [sortField]: order === 'asc' ? 1 : -1 };
            const products = await productCollection.find(filter).sort(sortOption).limit(Number(limit)).skip(Number(skip)).toArray();
            const total = await productCollection.countDocuments(filter);
            console.log(products)
            res.send({ products, total });
        });

        // Home Products (Show on Home)
        app.get('/home-products', async (req, res) => {
            const showOnHome = req.query.showOnHome === 'true';
            const result = await productCollection
                .find({ showOnHome: showOnHome })
                .limit(6)
                .toArray();
            return res.send(result);
        });

        // Product Details
        app.get('/product-details/:id', verifyFBToken, async (req, res) => {
            const result = await productCollection.findOne({ _id: new ObjectId(req.params.id) });
            res.send(result);
        });

        app.post("/payment-checkout-session", verifyFBToken, async (req, res) => {
            try {
                const { productId, quantity } = req.body;
                const product = await productCollection.findOne({ _id: new ObjectId(productId) });

                if (!product) return res.status(404).send({ message: "Product not found" });
                if (!product.paymentOption?.includes("Stripe"))
                    return res.status(400).send({ message: "Stripe payment not allowed" });
                if (quantity > product.availableQty)
                    return res.status(400).send({ message: "Insufficient stock" });

                const unitAmount = Math.round(product.price * 100);

                if (unitAmount * quantity > 99999999)
                    return res.status(400).send({ message: "Total amount exceeds Stripe limit" });

                const session = await stripe.checkout.sessions.create({
                    line_items: [{
                        price_data: {
                            currency: "usd",
                            unit_amount: unitAmount,
                            product_data: { name: product.name },
                        },
                        quantity
                    }],
                    mode: "payment",
                    metadata: {
                        productId: product._id.toString(),
                        productName: product.name,
                        quantity: quantity.toString(),
                        buyerEmail: req.decoded_email,
                        deliveryAddress: req.body.deliveryAddress || '',
                        notes: req.body.notes || '',
                        contactNumber: req.body.contactNumber || '',
                        userName: req.body.userName || ''
                    },
                    customer_email: req.decoded_email,
                    success_url: `${process.env.SITE_DOMAIN}/payment-success?session_id={CHECKOUT_SESSION_ID}`,
                    cancel_url: `${process.env.SITE_DOMAIN}/orderForm/${productId}`,
                });

                res.send({ url: session.url });

            } catch (err) {
                console.error(err);
                res.status(500).send({ message: "Stripe session error" });
            }
        });


        // Payment Success (Stripe) - Duplicate safe
        app.patch('/payment-success', async (req, res) => {
            try {
                const sessionId = req.query.session_id;
                const session = await stripe.checkout.sessions.retrieve(sessionId);

                // console.log('session retrieve', session)
                const transactionId = session.payment_intent;
                const query = { transactionId: transactionId }

                const paymentExist = await paymentCollection.findOne(query);
                const orderExist = await orderCollection.findOne(query)

                // console.log(paymentExist);
                if (paymentExist || orderExist) {
                    return res.send({
                        message: 'already exists',
                        transactionId,
                        trackingId: orderExist.trackingId
                    })
                }


                if (session.payment_status !== 'paid') {
                    return res.send({ success: false, message: 'Payment not completed' });
                }

                const trackingId = generateTrackingId();
                const quantity = Number(session.metadata.quantity);
                const amount = session.amount_total / 100;


                // Insert Order
                const order = {
                    transactionId,
                    buyerEmail: session.metadata.buyerEmail || session.customer_email,
                    productId: session.metadata.productId,
                    productName: session.metadata.productName,
                    quantity,
                    amount,
                    currency: session.currency,
                    paymentStatus: session.payment_status,
                    userName: session.metadata.userName,
                    deliveryAddress: session.metadata.deliveryAddress,
                    notes: session.metadata.notes,
                    contactNumber: session.metadata.contactNumber,
                    paidAt: new Date(),
                    orderDate: new Date(),
                    status: 'Pending',
                    paymentMethod: 'Stripe',
                    trackingId
                };
                await orderCollection.insertOne(order);

                // Insert Payment
                const paymentInfo = {
                    transactionId,
                    buyerEmail: session.metadata.buyerEmail || session.customer_email,
                    amount,
                    currency: session.currency,
                    paymentMethod: 'Stripe',
                    paidAt: new Date(),
                    trackingId: trackingId
                };
                await paymentCollection.insertOne(paymentInfo);
                const buyerEmail = session.customer_email;
                const productId = session.metadata.productId;
                // Update Product Stock
                await productCollection.updateOne({ _id: new ObjectId(productId), availableQty: { $gte: quantity } }, { $inc: { availableQty: -quantity } });


                // Log Tracking
                await logTracking(trackingId, 'Cutting Completed', buyerEmail);

                res.send({ success: true, trackingId, transactionId, paymentInfo: order });
            } catch (err) {
                console.error(err);
                res.status(500).send({ message: 'Stripe session error' });
            }
        });


        // COD Order
        app.post("/orders/cod", verifyFBToken, async (req, res) => {
            try {
                const { productId, quantity, contactNumber, deliveryAddress, notes, paymentMethod, userName } = req.body;
                const qty = Number(quantity);
                const product = await productCollection.findOne({ _id: new ObjectId(productId) });
                if (!product) return res.status(404).send({ message: "Product not found" });
                if (!product.paymentOption?.includes(paymentMethod)) return res.status(400).send({ message: `Payment method ${paymentMethod} not allowed` });
                if (qty > product.availableQty) return res.status(400).send({ message: "Insufficient stock" });

                const transactionId = crypto.randomUUID();

                // Duplicate check in both collections
                const paymentExist = await paymentCollection.findOne({ transactionId });
                const orderExist = await orderCollection.findOne({ transactionId });
                if (paymentExist || orderExist) {
                    const trackingId = paymentExist ? paymentExist.orderId : orderExist.trackingId;
                    return res.status(400).send({ message: 'Order already exists', transactionId, trackingId });
                }
                const trackingId = generateTrackingId()
                const order = {
                    trackingId: trackingId,
                    transactionId,
                    productId: product._id,
                    productName: product.name,
                    userName,
                    buyerEmail: req.decoded_email,
                    quantity: qty,
                    amount: qty * product.price,
                    paymentMethod,
                    paymentStatus: "Unpaid",
                    status: "Pending",
                    orderDate: new Date(),
                    contactNumber,
                    deliveryAddress,
                    notes,
                };


                await productCollection.updateOne({ _id: product._id, availableQty: { $gte: qty } }, { $inc: { availableQty: -qty } });
                await orderCollection.insertOne(order);

                const paymentInfo = {
                    transactionId,
                    buyerEmail: req.decoded_email,
                    amount: qty * product.price,
                    currency: 'usd',
                    paymentMethod: 'COD',
                    trackingId: trackingId
                };
                await paymentCollection.insertOne(paymentInfo);
                const buyerEmail = order.buyerEmail
                await logTracking(trackingId, 'Cutting Completed', buyerEmail);
                res.send({ success: true, message: "Order placed successfully (COD)", trackingId: order.orderId });

            } catch (err) {
                console.error(err);
                res.status(500).send({ message: "Server error" });
            }
        });

        // Buyer My Orders
        app.get('/buyer/my-orders', verifyFBToken, async (req, res) => {
            const buyerEmail = req.decoded_email;
            const myOrders = await orderCollection.find({ buyerEmail }).toArray();
            res.send(myOrders);
        })

        // cancel order only pending status
        app.patch('/buyer/cancel/order/:id', verifyFBToken, async (req, res) => {
            try {
                const email = req.query.email;
                const orderId = req.params.id;

                // Authorization check
                if (req.decoded_email !== email) {
                    return res.status(401).send({ message: 'Unauthorized Access' });
                }

                const query = { _id: new ObjectId(orderId) };
                const order = await orderCollection.findOne(query);

                if (!order) {
                    return res.status(404).send({ message: 'Order not found' });
                }

                // Only pending orders can be cancelled
                if (order.status !== 'Pending') {
                    return res.status(400).send({
                        message: `Order cannot be cancelled. Current status: ${order.status}`
                    });
                }

                // Update ONLY status
                const updateResult = await orderCollection.updateOne(
                    query,
                    {
                        $set: {
                            status: 'Cancelled',
                            cancelledAt: new Date()
                        }
                    }
                );

                if (updateResult.modifiedCount === 0) {
                    return res.status(400).send({ message: 'Order not updated' });
                }

                res.send({
                    success: true,
                    message: 'Order cancelled successfully',
                    orderId
                });

            } catch (error) {
                console.error(error);
                res.status(500).send({ message: 'Server error' });
            }
        });
        // manager products orders details
        app.get('/buyer/order/details/:orderId', verifyFBToken, managerVerify, async (req, res) => {
            const orderId = new ObjectId(req.params.orderId);
            const result = await orderCollection.findOne({
                _id: orderId,
            });
            if (!result) {
                return res.status(404).send({ message: 'Order not found' });
            }
            res.send(result);
        });
        // order details
        app.get('/orders/:orderId', verifyFBToken, async (req, res) => {
            try {
                const orderId = new ObjectId(req.params.orderId);
                const trackingId = req.query.trackingId;

                if (!trackingId) {
                    return res.status(400).send({ message: 'trackingId is required' });
                }

                const result = await orderCollection.aggregate([
                    // Match order by orderId + buyer
                    {
                        $match: {
                            _id: orderId,
                            buyerEmail: req.decoded_email,
                            trackingId: trackingId // extra safety
                        }
                    },

                    // Join tracking using query trackingId
                    {
                        $lookup: {
                            from: 'trackings',
                            let: { tId: trackingId },
                            pipeline: [
                                {
                                    $match: {
                                        $expr: {
                                            $eq: ['$trackingId', '$$tId']
                                        }
                                    }
                                },
                                { $sort: { createdAt: 1 } }
                            ],
                            as: 'tracking'
                        }
                    },

                    //Clean response
                    {
                        $project: {
                            buyerEmail: 0
                        }
                    }
                ]).toArray();

                if (!result.length) {
                    return res.status(404).send({ message: 'Order not found' });
                }

                res.send({ orderDetails: result[0] });

            } catch (error) {
                console.error(error);
                res.status(500).send({ message: 'Server error' });
            }
        });

        // approve order 
        app.get('/approved-orders/manager', verifyFBToken, managerVerify, async (req, res) => {
            const query = { status: 'Approved' };
            const orders = await orderCollection.find(query).toArray();
            res.send(orders);
        })

        // Manager Pending Orders (their products)
        app.get('/manager/pending-orders', verifyFBToken, managerVerify, async (req, res) => {
            const managerEmail = req.decoded_email;
            const products = await productCollection.find({ providerEmail: managerEmail }).toArray();
            const productIds = products.map(p => p._id.toString());

            const pendingOrders = await orderCollection.find({
                productId: { $in: productIds },
                status: 'Pending'
            }).toArray();

            res.send(pendingOrders);
        });
        // buyer orders
        app.get('/buyer/orders', verifyFBToken, async (req, res) => {
            try {
                const email = req.query.email;

                // Buyer verification
                if (req.decoded_email !== email) {
                    return res.status(403).send({
                        message: "Forbidden: You can only access your own orders"
                    });
                }

                // Pending orders count
                const OrdersCount = await orderCollection.countDocuments({
                    buyerEmail: email,
                });
                const pendingOrdersCount = await orderCollection.countDocuments({
                    buyerEmail: email,
                    status: "Pending"
                });

                // Cancelled orders count
                const cancelledOrdersCount = await orderCollection.countDocuments({
                    buyerEmail: email,
                    status: "Cancelled"
                });

                // Completed orders count (Out for Delivery)
                const completedOrdersCount = await trackingsCollection.countDocuments({
                    buyerEmail: email,
                    status: "Out for Delivery"
                });

                res.status(200).send({
                    totalOrders: OrdersCount,
                    pendingOrders: pendingOrdersCount,
                    cancelledOrders: cancelledOrdersCount,
                    completedOrders: completedOrdersCount
                });

            } catch (error) {
                console.error(error);
                res.status(500).send({ message: "Server Error" });
            }
        });
        // update products
        app.patch('/update-product/:id', verifyFBToken, managerVerify, async (req, res) => {
            const email = req.query.email;
            const id = req.params.id
            const updateData = req.body;
            const query = { _id: new ObjectId(id) }
            if (req.decoded_email !== email) {
                return res.status(403).send({ message: 'Forbidden access' })
            }
            const newUpdateData = {
                $set: {
                    name: updateData.name,
                    category: updateData.category,
                    description: updateData.description,
                    price: updateData.price,
                    minOrderQty: updateData.minOrderQty,
                    availableQty: updateData.availableQty,
                    showOnHome: updateData.showOnHome,
                    image: updateData.image,
                    providerEmail: req.decoded_email,
                    paymentOption: updateData.paymentOption,
                    demoLink: updateData.demoLink,
                }
            }

            const result = await productCollection.updateOne(query, newUpdateData);
            res.send(result)

        })



        // admin update products
        app.patch('/update-product/admin/:id', verifyFBToken, adminVerify, async (req, res) => {
            const email = req.query.email;
            const id = req.params.id
            const updateData = req.body;
            const query = { _id: new ObjectId(id) }
            console.log('id', id);
            console.log('updateData', updateData);
            if (req.decoded_email !== email) {
                return res.status(403).send({ message: 'Forbidden access' })
            }
            const newUpdateData = {
                $set: {
                    name: updateData.name,
                    category: updateData.category,
                    description: updateData.description,
                    price: updateData.price,
                    minOrderQty: updateData.minOrderQty,
                    availableQty: updateData.availableQty,
                    showOnHome: updateData.showOnHome,
                    image: updateData.image,
                    providerEmail: req.decoded_email,
                    paymentOption: updateData.paymentOption,
                    demoLink: updateData.demoLink,
                }
            }

            const result = await productCollection.updateOne(query, newUpdateData);
            res.send(result)

        })

        // 


        app.delete('/product/admin/:id', verifyFBToken, adminVerify, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            const result = await productCollection.deleteOne(query);
            res.send(result);
        })

        // order details
        app.get('/orders/details/:orderId', verifyFBToken, adminVerify, async (req, res) => {
            try {
                const orderId = new ObjectId(req.params.orderId);
                const trackingId = req.query.trackingId;

                if (!trackingId) {
                    return res.status(400).send({ message: 'trackingId is required' });
                }

                const result = await orderCollection.aggregate([
                    // Match order by _id and trackingId
                    {
                        $match: {
                            _id: orderId,
                            trackingId: trackingId
                        }
                    },

                    // Lookup tracking info
                    {
                        $lookup: {
                            from: 'trackings',
                            let: { tId: trackingId },
                            pipeline: [
                                {
                                    $match: {
                                        $expr: { $eq: ['$trackingId', '$$tId'] }
                                    }
                                },
                                { $sort: { createdAt: 1 } }
                            ],
                            as: 'tracking'
                        }
                    },

                    // Project all fields (include buyerEmail for admin)
                    {
                        $project: {
                            transactionId: 1,
                            buyerEmail: 1,
                            productId: 1,
                            productName: 1,
                            userName: 1,
                            contactNumber: 1,
                            deliveryAddress: 1,
                            notes: 1,
                            quantity: 1,
                            amount: 1,
                            currency: 1,
                            paymentStatus: 1,
                            paidAt: 1,
                            orderDate: 1,
                            status: 1,
                            paymentMethod: 1,
                            trackingId: 1,
                            cancelledAt: 1,
                            createdAt: 1,
                            tracking: 1

                        }
                    }
                ]).toArray();

                if (!result.length) {
                    return res.status(404).send({ message: 'Order not found' });
                }

                res.send({ orderDetails: result[0] });

            } catch (error) {
                console.error(error);
                res.status(500).send({ message: 'Server error' });
            }
        });
        // pending orders
        app.get('/pending-orders/manager', verifyFBToken, managerVerify, async (req, res) => {
            const orders = await orderCollection.find({ status: 'Pending' }).toArray();
            res.send(orders)
        })
        // approve order
        app.patch('/approved-order/:id', verifyFBToken, managerVerify, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            const updateDoc = {
                $set: {
                    status: 'Approved',
                    approvedAt: new Date()
                }
            }
            const result = await orderCollection.updateOne(query, updateDoc);
            res.send(result)
        })

        // reject order
        app.patch('/reject-order/:id', verifyFBToken, managerVerify, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            const updateDoc = {
                $set: {
                    status: 'Rejected',
                    rejectedAt: new Date()
                }
            }
            const result = await orderCollection.updateOne(query, updateDoc);
            res.send(result)
        })

        // all orders admin
        app.get('/all-orders/admin', verifyFBToken, adminVerify, async (req, res) => {
            const orders = await orderCollection.find({}).toArray();
            res.send(orders)
        })
        //orders tracking related apis
        app.post('/trackings/order-update', verifyFBToken, managerVerify, async (req, res) => {
            const { trackingId, status, notes, location, buyerEmail, dateTime } = req.body;
            const result = await logTracking(trackingId, status, buyerEmail, dateTime, location, notes);
            res.send(result);
        });

        //   manager profile
        app.get('/manager/profile/:email', verifyFBToken, managerVerify, async (req, res) => {
            try {
                const email = req.params.email;

                // 1. Find all products for this provider
                const products = await productCollection.find({ providerEmail: email }).toArray();
                const totalProducts = products.length;

                // 2. Prepare counters
                let totalOrders = 0;
                let pendingOrders = 0;
                let approvedOrders = 0;
                let rejectedOrders = 0;

                // 3. Loop through each product to check orders
                for (const product of products) {
                    const orders = await orderCollection.find({ productId: product._id }).toArray();
                    totalOrders += orders.length;

                    orders.forEach(order => {
                        if (order.status === "Pending") pendingOrders++;
                        if (order.status === "Approved") approvedOrders++;
                        if (order.status === "Rejected") rejectedOrders++;
                    });
                }

                // 4. Return the summary
                res.json({
                    providerEmail: email,
                    totalProducts,
                    totalOrders,
                    pendingOrders,
                    approvedOrders,
                    rejectedOrders
                });

            } catch (error) {
                console.error(error);
                res.status(500).json({ message: "Internal server error" });
            }
        });
        //   manager profile
        app.get('/admin/profile/:email', verifyFBToken, adminVerify, async (req, res) => {
            try {
                const email = req.params.email;

                const totalUsers = await usersCollection.countDocuments();
                const totalSuspendedUsers = await usersCollection.countDocuments({ status: "suspended" });
                const totalPendingUsers = await usersCollection.countDocuments({ status: "pending" });
                const totalProducts = await productCollection.countDocuments();
                const totalOrders = await orderCollection.countDocuments();

                // Optional: Count orders by status
                const pendingOrders = await orderCollection.countDocuments({ status: "Pending" });
                const approvedOrders = await orderCollection.countDocuments({ status: "Approved" });
                const rejectedOrders = await orderCollection.countDocuments({ status: "Rejected" });

                res.json({
                    adminEmail: email,
                    totalUsers,
                    totalPendingUsers,
                    totalSuspendedUsers,
                    totalProducts,
                    totalOrders,
                    pendingOrders,
                    approvedOrders,
                    rejectedOrders
                });

            } catch (error) {
                console.error(error);
                res.status(500).json({ message: "Internal server error" });
            }
        });


        // app.get('/manager/profile/:email', verifyFBToken, managerVerify, async (req, res) => {
        //     try {
        //         const email = req.params.email;

        //         const result = await productCollection.aggregate([
        //             { $match: { providerEmail: email } }, // ওই manager এর products
        //             {
        //                 $lookup: {
        //                     from: "orderCollection",
        //                     let: { pid: "$_id" },
        //                     pipeline: [
        //                         {
        //                             $match: {
        //                                 $expr: {
        //                                     $eq: ["$productId", { $toString: "$$pid" }] // ObjectId -> string
        //                                 }
        //                             }
        //                         }
        //                     ],
        //                     as: "orders"
        //                 }
        //             },
        //             {
        //                 $project: {
        //                     totalOrders: { $size: "$orders" },
        //                     pendingOrders: {
        //                         $size: {
        //                             $filter: { input: "$orders", cond: { $eq: ["$$this.status", "Pending"] } }
        //                         }
        //                     },
        //                     approvedOrders: {
        //                         $size: {
        //                             $filter: { input: "$orders", cond: { $eq: ["$$this.status", "Approved"] } }
        //                         }
        //                     },
        //                     rejectedOrders: {
        //                         $size: {
        //                             $filter: { input: "$orders", cond: { $eq: ["$$this.status", "Rejected"] } }
        //                         }
        //                     }
        //                 }
        //             },
        //             {
        //                 $group: {
        //                     _id: null,
        //                     totalProducts: { $sum: 1 },
        //                     totalOrders: { $sum: "$totalOrders" },
        //                     pendingOrders: { $sum: "$pendingOrders" },
        //                     approvedOrders: { $sum: "$approvedOrders" },
        //                     rejectedOrders: { $sum: "$rejectedOrders" }
        //                 }
        //             }
        //         ]).toArray();
        //         res.json({
        //             providerEmail: email,
        //             totalProducts: result[0]?.totalProducts || 0,
        //             totalOrders: result[0]?.totalOrders || 0,
        //             pendingOrders: result[0]?.pendingOrders || 0,
        //             approvedOrders: result[0]?.approvedOrders || 0,
        //             rejectedOrders: result[0]?.rejectedOrders || 0
        //         });

        //     } catch (error) {
        //         console.error(error);
        //         res.status(500).json({ message: "Internal server error" });
        //     }
        // });
        // app.get('/manager/profile/:email', verifyFBToken, managerVerify, async (req, res) => {
        //     try {
        //         const email = req.params.email;

        //         const result = await productCollection.aggregate([
        //             { $match: { providerEmail: email } }, // ওই provider এর প্রোডাক্ট
        //             {
        //                 $lookup: {  // orderCollection এর সাথে join
        //                     from: "orderCollection",
        //                     let: { pid: "$_id" },
        //                     pipeline: [
        //                         {
        //                             $match: {
        //                                 $expr: {
        //                                     $eq: ["$productId", { $toString: "$$pid" }]
        //                                 }
        //                             }
        //                         }
        //                     ],
        //                     as: "orders"
        //                 }
        //             },
        //             {
        //                 $project: {
        //                     totalOrders: { $size: "$orders" },
        //                     pendingOrders: {
        //                         $size: {
        //                             $filter: { input: "$orders", cond: { $eq: ["$$this.status", "Pending"] } }
        //                         }
        //                     },
        //                     approvedOrders: {
        //                         $size: {
        //                             $filter: { input: "$orders", cond: { $eq: ["$$this.status", "Approved"] } }
        //                         }
        //                     },
        //                     rejectedOrders: {
        //                         $size: {
        //                             $filter: { input: "$orders", cond: { $eq: ["$$this.status", "Rejected"] } }
        //                         }
        //                     }
        //                 }
        //             },
        //             {
        //                 $group: {
        //                     _id: null,
        //                     totalProducts: { $sum: 1 },
        //                     totalOrders: { $sum: "$totalOrders" },
        //                     pendingOrders: { $sum: "$pendingOrders" },
        //                     approvedOrders: { $sum: "$approvedOrders" },
        //                     rejectedOrders: { $sum: "$rejectedOrders" }
        //                 }
        //             }
        //         ]).toArray();

        //         res.json({
        //             providerEmail: email,
        //             totalProducts: result[0]?.totalProducts || 0,
        //             totalOrders: result[0]?.totalOrders || 0,
        //             pendingOrders: result[0]?.pendingOrders || 0,
        //             approvedOrders: result[0]?.approvedOrders || 0,
        //             rejectedOrders: result[0]?.rejectedOrders || 0
        //         });

        //     } catch (error) {
        //         console.error(error);
        //         res.status(500).json({ message: "Internal server error" });
        //     }
        // });





        // get tracking logs by trackingId


        app.get('/trackings/:trackingId', verifyFBToken, async (req, res) => {
            const trackingId = req.params.trackingId;
            const logs = await trackingsCollection.find({ trackingId }).sort({ createdAt: 1 }).toArray();
            res.send(logs);
        });

        app.get('/buyer/trackOrders', verifyFBToken, async (req, res) => {
            try {
                const { searchTrackingId } = req.query;

                // if (!searchTrackingId || searchTrackingId.trim() === "") {
                //     return res.status(400).json({
                //         success: false,
                //         message: "Tracking ID is required",
                //     });
                // }


                const keyword = searchTrackingId.trim();

                //prefix search (cut word match)
                const trackingSteps = await trackingsCollection
                    .find({
                        trackingId: {
                            $gte: keyword,
                            $lt: keyword + "z"   // ensures prefix match
                        }
                    })
                    .sort({ createdAt: 1 })
                    .toArray();
                console.log(trackingSteps)

                res.status(200).json({
                    success: true,
                    keyword,
                    totalSteps: trackingSteps.length,
                    data: trackingSteps,
                });

            } catch (error) {
                console.error("Track order error:", error);
                res.status(500).json({
                    success: false,
                    message: "Internal server error",
                });
            }
        });


        // Health check
        app.get('/', (req, res) => {
            res.send('GarmentFlow server is running...');
        });

        await client.db("admin").command({ ping: 1 });
        console.log("Connected to MongoDB successfully!");

    } finally {
        // Optional: client.close();
    }
}
run().catch(console.dir);

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
