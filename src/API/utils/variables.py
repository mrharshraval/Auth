# Extra Functions 
from django.conf            import settings

DEFAULT_ACTIVATION_MINUTES = getattr(settings, 'DEFAULT_ACTIVATION_MINUTES', 60)

# Choice fields
ACTIVE      = 'Active'

DEPOSIT     = 'Deposit'
DRAFT       = 'Draft'

EMPLOYEE    = "Employee"
EXCLUDED    = "Excluded"

FEMALE      = "Female"

HOME        = "Home"

MANAGER     = "Manager"
MALE        = "Male"

OWNER       = "Owner"
OTHER       = "Other"

SOLDOUT     = 'Soldout'
STAFF       = "Staff"

WITHDRAWAL  = 'Withdrawal'
WORK        = "Work"


# Choice fields
ACTIVE      = 'Active'

DEPOSIT     = 'Deposit'
DRAFT       = 'Draft'

EMPLOYEE    = "Employee"
EXCLUDED    = "Excluded"

FEMALE      = "Female"

INCLUDED    = "Included"

HOME        = "Home"

MANAGER     = "Manager"
MALE        = "Male"

OWNER       = "Owner"
OTHER       = "Other"

SOLDOUT     = 'Soldout'
STAFF       = "Staff"

WITHDRAWAL  = 'Withdrawal'
WORK        = "Work"



ADDRESS_TYPE    = [
    (HOME,  'Home'),
    (WORK,  'Work'),
    (OTHER, 'Other')
]


GENDER          = [
    (MALE,      'Male'),
    (FEMALE,    'Female')
]


MONTHS          = [
    (1, 'January'),
    (2, 'February'),
    (3, 'March'),
    (4, 'April'),
    (5, 'May'),
    (6, 'June'),
    (7, 'July'),
    (8, 'August'),
    (9, 'September'),
    (10, 'October'),
    (11, 'November'),
    (12, 'December')
]


ORDER_STATUS    = [
    ('ORDER_RECEIVED',      'Order Received'),
    ('PAYMENT_PROCESSING',  'Payment Processing'),
    ('PAYMENT_FAILED',      'Payment Failed'),
    ('PROCESSING',          'Processing'),
    ('BACKORDERED',         'Backordered'),
    ('ON_HOLD',             'On Hold'),
    ('READY_FOR_PICKUP',    'Ready for Pickup'),
    ('SHIPPED',             'Shipped'),
    ('IN_TRANSIT',          'In Transit'),
    ('OUT_FOR_DELIVERY',    'Out for Delivery'),
    ('DELIVERED',           'Delivered'),
    ('RETURNED',            'Returned'),
    ('REFUNDED',            'Refunded'),
    ('CANCELLED',           'Cancelled'),
    ('PARTIALLY_SHIPPED',   'Partially Shipped'),
    ('AWAITING_PICKUP',     'Awaiting Pickup'),
    ('AWAITING_SHIPMENT',   'Awaiting Shipment'),
    ('AWAITING_FULFILLMENT', 'Awaiting Fulfillment')
]



PRODUCT_STATUS = [    
    ('ACTIVE',              'Active'),    
    ('DRAFT',               'Draft'),    
    ('SOLD_OUT',            'Sold Out'),    
    ('OUT_OF_STOCK',        'Out of Stock'),    
    ('DISCONTINUED',        'Discontinued'),    
    ('ON_BACKORDER',        'On Backorder'),    
    ('COMING_SOON',         'Coming Soon'),    
    ('PRE_ORDER',           'Pre-order'),    
    ('NEW_ARRIVAL',         'New Arrival'),    
    ('LIMITED_EDITION',     'Limited Edition'),    
    ('CLEARANCE',           'Clearance'),    
    ('REFURBISHED',         'Refurbished'),    
    ('USED',                'Used'),    
    ('RETURNED',            'Returned'),    
    ('DEFECTIVE',           'Defective')
]



ROLE            = [
    (OWNER,     'Owner'),
    (MANAGER,   'Manager'),
    (EMPLOYEE,  'Employee'),
    (STAFF,     'Staff')
]


TAX_PREFERENCES = [
    (EXCLUDED,  'Excluded'),
    (INCLUDED,  'Included')
]

SOCIALMEDIA_PLATFORM = [    
    ('Facebook',    'Facebook'),    
    ('Twitter',     'Twitter'),    
    ('Instagram',   'Instagram'),    
    ('LinkedIn',    'LinkedIn'),    
    ('Snapchat',    'Snapchat'),    
    ('TikTok',      'TikTok'),    
    ('Pinterest',   'Pinterest'),    
    ('Reddit',      'Reddit'),    
    ('YouTube',     'YouTube'),    
    ('WhatsApp',    'WhatsApp'),    
    ('Telegram',    'Telegram'),    
    ('WeChat',      'WeChat'),    
    ('Line',        'Line'),    
    ('Signal',      'Signal'),    
    ('Viber',       'Viber'),    
    ('Skype',       'Skype'),
]


GST_TAX_RATES = [    
    ('0%',      '0% (Exempted Goods)'),    
    ('0.25%',   '0.25% (Diamonds and precious stones)'),    
    ('3%',      '3% (Gold)'),    
    ('5%',      '5% (Essential goods and services)'),    
    ('12%',     '12% (Standard rate)'),    
    ('18%',     '18% (Standard rate)'),    
    ('28%',     '28% (Luxury goods and services)')
]


TRANSACTION     = [
    (DEPOSIT,       'Deposit'),
    (WITHDRAWAL,    'Withdrawal'),
]


WEEKDAYS        = [
    (1, 'Monday'),
    (2, 'Tuesday'),
    (3, 'Wednesday'),
    (4, 'Thursday'),
    (5, 'Friday'),
    (6, 'Saturday'),
    (7, 'Sunday'),
]