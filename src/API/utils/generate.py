import math, random, string
from django.utils.text      import slugify
from django.db.models       import Model

def GenerateOTP() : 
    # Declare a digits variable 
    # which stores all digits 
    digits  = "0123456789"
    OTP     = "" 

    # length of password can be changed 
    # by changing value in range 
    for i in range(6) : 
        OTP += digits[math.floor(random.random() * 10)] 

    return OTP


def GenerateUniqueNumber(instance, length) : 
    # Declare a digits variable 
    # which stores all digits 
    unique = ''.join(random.choices(string.digits, k=length))

    Klass = instance.__class__
    qs_exists = Klass.objects.filter(code=unique).exists()

    if qs_exists:
        return GenerateUniqueNumber(instance, length)

    return unique


def GenerateUniqueBarcode(instance, length) : 
    # Declare a digits variable 
    # which stores all digits 
    unique = ''.join(random.choices(string.digits, k=length))

    if issubclass(instance.__class__, Model):
        Klass = instance.__class__
        qs_exists = Klass.objects.filter(code=unique).exists()

        if qs_exists:
            return GenerateUniqueBarcode(instance, length)

    return unique

# Renamed : random string generator => GenerateRandomString


def GenerateRandomString(size=10, chars=string.ascii_lowercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


# Renamed : unique key generator => GenerateUniqueKey


def GenerateUniqueKey(instance):
    """
    This is for a Django project with an key field
    """
    size = random.randint(30, 45)
    link = GenerateRandomString(size=size)

    Klass = instance.__class__
    qs_exists = Klass.objects.filter(link=link).exists()
    if qs_exists:
        return GenerateUniqueSlug(instance)
    return link


# Renamed : unique slug generator => GenerateUniqueSlug

def GenerateUniqueSlug(instance, new_slug=None):
    """
    This is for a Django project and it assumes your instance 
    has a model with a slug field and a title character (char) field.
    """
    if new_slug is not None:
        slug = new_slug
    else:
        slug = slugify(instance.title)

    Klass = instance.__class__
    qs_exists = Klass.objects.filter(slug=slug).exists()
    if qs_exists:
        new_slug = "{slug}-{randstr}".format(
                    slug=slug,
                    randstr=GenerateRandomString(size=4)
                )
        return GenerateUniqueSlug(instance, new_slug=new_slug)
    return slug
