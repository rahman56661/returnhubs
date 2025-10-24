// routes/organizationSettings.js
const OrganizationSettings = require('../models/OrganizationSettings');

router.post('/save-organization-settings', async (req, res) => {
    try {
        const { organizationId, settings } = req.body;

        // UPSERT operation - idha use pannu
        const result = await OrganizationSettings.findOneAndUpdate(
            { organizationId: organizationId },
            {
                ...settings,
                updatedAt: new Date()
            },
            {
                upsert: true, // idhu important - create if not exists
                new: true
            }
        );

        console.log('✅ Settings saved to DB:', result);
        res.json({ success: true, message: 'Settings saved permanently' });
    } catch (error) {
        console.error('❌ Settings save error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

router.get('/get-organization-settings/:orgId', async (req, res) => {
    try {
        const { orgId } = req.params;

        const settings = await OrganizationSettings.findOne({ organizationId: orgId });

        if (settings) {
            console.log('✅ Settings loaded from DB:', settings);
            res.json(settings);
        } else {
            // Default settings return pannu
            const defaultSettings = {
                courierName: ['Amazon', 'Delhivery', 'DTDC', 'Other'],
                returnType: ['RTO', 'RVP', 'Other'],
                opsRemarks: ['Good', 'Damaged', 'Missing Items', 'Other'],
                channelName: ['Shopify', 'Amazon', 'Flipkart', 'Other']
            };
            res.json(defaultSettings);
        }
    } catch (error) {
        console.error('❌ Settings load error:', error);
        res.status(500).json({ error: error.message });
    }
});