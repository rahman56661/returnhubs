// middleware/orgAuth.js
const orgAuth = (req, res, next) => {
    try {
        const user = req.user;
        if (!user.org_id) {
            return res.status(403).json({ 
                success: false, 
                message: "Organization access denied" 
            });
        }
        
        req.org_id = user.org_id;
        req.org_db = `org_${user.org_id}_db`;
        next();
    } catch (error) {
        res.status(500).json({ success: false, message: "Org auth failed" });
    }
};

module.exports = { orgAuth };