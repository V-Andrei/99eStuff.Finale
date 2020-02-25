CREATE DATABASE ninetyNineEStuff;

CREATE TABLE Products
(
	ID int not null primary key,
	NameProduct varchar(50) not null,
	Category varchar(20) not null,
	Stock int not null,
	CurentPrice money not null,
	OldPrice money not null,
	SmallPicture image,
	BigPicture image,
	[Description] text,
	Detail1 varchar(200),
	Detail2 varchar(200),
	Detail3 varchar(200),
	Detail4 varchar(200)
);

CREATE TABLE ContactData
(
	IdClient int not null primary key IDENTITY(1,1),
	NameClient varchar(100) not null,
	Mail varchar(100) not null,
	City varchar(100) not null,
	[Message] text
)

CREATE TABLE UserData
(
	IdUser int not null primary key IDENTITY(1,1),
	UserName varchar(100) not null,
	[Password] varchar(200) not null,
	Mail varchar(100) not null,
	NameClient varchar(100) not null, 
)

insert into dbo.Products
	([ID],[NameProduct],[Category],[Stock],[CurentPrice],[OldPrice],[SmallPicture],[BigPicture],[Detail1],[Detail2],[Detail3],[Detail4],[Description])
	values
	(
	1,
	'Money Belt',
	'Security',
	9,
	51.99,
	51.99,
	(SELECT * FROM OPENROWSET(BULK N'D:\Wantsome\TheProject\99eStuff\ProductImg\SmallImages\1.jpg', SINGLE_BLOB) as Img1),
	(SELECT * FROM OPENROWSET(BULK N'D:\Wantsome\TheProject\99eStuff\ProductImg\BigImages\1.jpg', SINGLE_BLOB) as Img1),
	'Carry passports, tickets & credit cards',
	'11 Well-proportioned compartments',
	'Zip-around design for total security',
	'Safe & convenient',
	'Providing a safe and convenient way to carry all of your holiday documents in one place, this travel wallet will organise even the most chaotic traveller. Ideal for storing passports, tickets and credit cards, 11 well-proportioned compartments offer quick and easy access to all your travel essentials for a smoother journey.'
	);
insert into dbo.Products
	([ID],[NameProduct],[Category],[Stock],[CurentPrice],[OldPrice],[SmallPicture],[BigPicture],[Detail1],[Detail2],[Detail3],[Detail4],[Description])
	values
	(
	2,
	'Travel Wallet',
	'Security',
	2,
	34.89,
	41.25,
	(SELECT * FROM OPENROWSET(BULK N'D:\Wantsome\TheProject\99eStuff\ProductImg\SmallImages\2.jpg', SINGLE_BLOB) as Img2),
	(SELECT * FROM OPENROWSET(BULK N'D:\Wantsome\TheProject\99eStuff\ProductImg\BigImages\2.jpg', SINGLE_BLOB) as Img2),
	'Made from breathable, skin-soft fabrics',
	'Ultra comfy & easy to wear',
	'Conceals valuables under clothing',
	'Fully adjustable, one size fits all',
	'Inspired by the soft and supple nature of lingerie, this feminine money belt is made from breathable, skin-soft fabrics. Beautifully stretchy and oh so comfy, its good looks don''t detract from its core function; to protect your valuables. A single zipped compartment and internal pocket discretely conceals belongings under clothing for peace of mind when out and about.'
	);
insert into dbo.Products
	([ID],[NameProduct],[Category],[Stock],[CurentPrice],[OldPrice],[SmallPicture],[BigPicture],[Detail1],[Detail2],[Detail3],[Detail4],[Description])
	values
	(
	3,
	'Body Pocket',
	'Security',
	4,
	44.99,
	44.99,
	(SELECT * FROM OPENROWSET(BULK N'D:\Wantsome\TheProject\99eStuff\ProductImg\SmallImages\3.jpg', SINGLE_BLOB) as Img3),
	(SELECT * FROM OPENROWSET(BULK N'D:\Wantsome\TheProject\99eStuff\ProductImg\BigImages\3.jpg', SINGLE_BLOB) as Img3),
	'Fits most passports worldwide',
	'Safeguards against data theft & digital crime',
	'Handcrafted in soft nappa leather',
	'Protects passport from wear & tear',
	'Handcrafted in soft nappa leather, this ultra sleek passport cover not only looks smart, it protects your passport from wear and tear. Designed to block illegal scans of RFID chips embedded in modern-day passports, it helps prevent identity theft by stopping sensitive personal data from being stolen. Slimline and stylish, this travel must-have fits most passports worldwide.'
	);
insert into dbo.Products
	([ID],[NameProduct],[Category],[Stock],[CurentPrice],[OldPrice],[SmallPicture],[BigPicture],[Detail1],[Detail2],[Detail3],[Detail4],[Description])
	values
	(
	4,
	'Passport Holder',
	'Security',
	14,
	25.75,
	35.60,
	(SELECT * FROM OPENROWSET(BULK N'D:\Wantsome\TheProject\99eStuff\ProductImg\SmallImages\4.jpg', SINGLE_BLOB) as Img4),
	(SELECT * FROM OPENROWSET(BULK N'D:\Wantsome\TheProject\99eStuff\ProductImg\BigImages\4.jpg', SINGLE_BLOB) as Img4),
	'Protects passports, money & other valuables',
	'Designed to be worn under clothing',
	'Unisex styling',
	'Includes 2 secure zipped compartments',
	'Slimline enough to wear under clothing and discreet enough to protect your belongings, this passport pouch is an essential travel companion. Its soft, comfy exterior makes it suitable for wearing on long journeys, while the 2 zipped front pockets protect passports, money and other valuables. A handy mesh compartment on the reverse ensures a place for everything.'
	);
insert into dbo.Products
	([ID],[NameProduct],[Category],[Stock],[CurentPrice],[OldPrice],[SmallPicture],[BigPicture],[Detail1],[Detail2],[Detail3],[Detail4],[Description])
	values
	(
	5,
	'Passport Pouch',
	'Security',
	6,
	18.00,
	26.33,
	(SELECT * FROM OPENROWSET(BULK N'D:\Wantsome\TheProject\99eStuff\ProductImg\SmallImages\5.jpg', SINGLE_BLOB) as Img5),
	(SELECT * FROM OPENROWSET(BULK N'D:\Wantsome\TheProject\99eStuff\ProductImg\BigImages\5.jpg', SINGLE_BLOB) as Img5),
	'RFID travel organiser',
	'Carry passports, cards & money together',
	'Blocks illegal RFID scanning equipment',
	'Protects against identity theft & digital crime',
	'An essential piece of kit for any well-organised traveller, this travel document holder offers the added security of RFID protection. Designed to block illegal scans of RFID chips embedded in modern-day passports and credits cards, it stops highly sensitive personal data from being stolen. 18 well-organised compartments offer ample storage for everything from travel documents and tickets to passports and credit cards.'
	);
insert into dbo.Products
	([ID],[NameProduct],[Category],[Stock],[CurentPrice],[OldPrice],[SmallPicture],[BigPicture],[Detail1],[Detail2],[Detail3],[Detail4],[Description])
	values
	(
	6,
	'Organiser',
	'Security',
	7,
	32.66,
	32.66,
	(SELECT * FROM OPENROWSET(BULK N'D:\Wantsome\TheProject\99eStuff\ProductImg\SmallImages\6.jpg', SINGLE_BLOB) as Img6),
	(SELECT * FROM OPENROWSET(BULK N'D:\Wantsome\TheProject\99eStuff\ProductImg\BigImages\6.jpg', SINGLE_BLOB) as Img6),
	'RFID travel organiser',
	'Carry passports, cards & money together',
	'Blocks illegal RFID scanning equipment',
	'Protects against identity theft & digital crime',
	'An essential piece of kit for any well-organised traveller, this travel document holder offers the added security of RFID protection. Designed to block illegal scans of RFID chips embedded in modern-day passports and credits cards, it stops highly sensitive personal data from being stolen. 18 well-organised compartments offer ample storage for everything from travel documents and tickets to passports and credit cards.'
	);
insert into dbo.Products
	([ID],[NameProduct],[Category],[Stock],[CurentPrice],[OldPrice],[SmallPicture],[BigPicture],[Detail1],[Detail2],[Detail3],[Detail4],[Description])
	values
	(
	7,
	'Micro Wallet',
	'Security',
	16,
	44.22,
	44.22,
	(SELECT * FROM OPENROWSET(BULK N'D:\Wantsome\TheProject\99eStuff\ProductImg\SmallImages\7.jpg', SINGLE_BLOB) as Img7),
	(SELECT * FROM OPENROWSET(BULK N'D:\Wantsome\TheProject\99eStuff\ProductImg\BigImages\7.jpg', SINGLE_BLOB) as Img7),
	'Blocks RFID scanning equipment',
	'Protects against identity theft and digital crime',
	'Secure magnetic closure',
	'Dual function card view window allows you to effortlessly slide out a card',
	'Stop digital pickpockets in their tracks with this stylish tri-fold RFID wallet. Ensuring that you don’t become a victim of digital fraud, this large capacity wallet integrates an RFID shield to safeguard all of your sensitive, secure data embedded in bank card chips. A large pocket is perfect for notes and a boarding pass, while the multiple card slots have a convenient dual function view window which not only allows you to instantly identify your card but also slide it effortlessly out of the slot. A secure and simple-to-use magnetic closure offers extra peace of mind.'
	);
insert into dbo.Products
	([ID],[NameProduct],[Category],[Stock],[CurentPrice],[OldPrice],[SmallPicture],[BigPicture],[Detail1],[Detail2],[Detail3],[Detail4],[Description])
	values
	(
	8,
	'Zip It',
	'Bags',
	30,
	5.11,
	5.11,
	(SELECT * FROM OPENROWSET(BULK N'D:\Wantsome\TheProject\99eStuff\ProductImg\SmallImages\8.jpg', SINGLE_BLOB) as Img8),
	(SELECT * FROM OPENROWSET(BULK N'D:\Wantsome\TheProject\99eStuff\ProductImg\BigImages\8.jpg', SINGLE_BLOB) as Img8),
	'Secure zip lock seal',
	'Airtight, strong & reusable',
	'2 Large, 3 small bags per pack',
	'Organise toiletries, snacks & electricals',
	'These extra strength packing bags make preparing for travel as easy as 1,2,3. Simply fill, zip and pack for a tidy suitcase or bag in seconds. The secure zip lock closure creates an airtight seal ideal for wet clothing, toiletries, electricals and more. Take them with you on any journey and keep your belongings organised and dry.'
	);
insert into dbo.Products
	([ID],[NameProduct],[Category],[Stock],[CurentPrice],[OldPrice],[SmallPicture],[BigPicture],[Detail1],[Detail2],[Detail3],[Detail4],[Description])
	values
	(
	9,
	'Laundry Bag',
	'Bags',
	18,
	13.33,
	15.44,
	(SELECT * FROM OPENROWSET(BULK N'D:\Wantsome\TheProject\99eStuff\ProductImg\SmallImages\9.jpg', SINGLE_BLOB) as Img9),
	(SELECT * FROM OPENROWSET(BULK N'D:\Wantsome\TheProject\99eStuff\ProductImg\BigImages\9.jpg', SINGLE_BLOB) as Img9),
	'Travel laundry bag with 15 litre capacity',
	'Separate dirty and clean laundry',
	'Buckled loop to hang easily at destination',
	'Drawstring closure to help seal the dirty laundry inside the bag',
	'Designated dirty clothes storage for your luggage, this large capacity bag has a drawstring closure to prevent odours and protect clean, pristine items from smelly, soiled ones. A large buckled loop makes it easy to hang at your destination. Compact and lightweight when packed, you can pop it in your machine at home with your dirty clothes to keep it fresh and clean. Part of the new, co-ordinated Packing Prepared range, it is the perfect packing companion for the Twin and Triple Packing Cubes, and the Wet or Dry Bag.'
	);
insert into dbo.Products
	([ID],[NameProduct],[Category],[Stock],[CurentPrice],[OldPrice],[SmallPicture],[BigPicture],[Detail1],[Detail2],[Detail3],[Detail4],[Description])
	values
	(
	10,
	'Backpack',
	'Bags',
	5,
	48.00,
	48.00,
	(SELECT * FROM OPENROWSET(BULK N'D:\Wantsome\TheProject\99eStuff\ProductImg\SmallImages\10.jpg', SINGLE_BLOB) as Img10),
	(SELECT * FROM OPENROWSET(BULK N'D:\Wantsome\TheProject\99eStuff\ProductImg\BigImages\10.jpg', SINGLE_BLOB) as Img10),
	'Compresses in seconds for easy storage',
	'Use as hand luggage or pack in your case',
	'Ideal for exploring & adventuring',
	'Strong & comfortable to wear',
	'An easy way to lighten the load, this strong yet feather light travel backpack folds to a fraction of its size when not in use. Cabin approved as well as convenient to pack, use it as hand luggage or squeeze it into your suitcase and take it on your travels. Ideal for any activity or adventure holiday, it is comfortable to wear all day.'
	);
insert into dbo.Products
	([ID],[NameProduct],[Category],[Stock],[CurentPrice],[OldPrice],[SmallPicture],[BigPicture],[Detail1],[Detail2],[Detail3],[Detail4],[Description])
	values
	(
	11,
	'Travel Bag',
	'Bags',
	2,
	65.12,
	68.33,
	(SELECT * FROM OPENROWSET(BULK N'D:\Wantsome\TheProject\99eStuff\ProductImg\SmallImages\11.jpg', SINGLE_BLOB) as Img11),
	(SELECT * FROM OPENROWSET(BULK N'D:\Wantsome\TheProject\99eStuff\ProductImg\BigImages\11.jpg', SINGLE_BLOB) as Img11),
	'Compresses in seconds for easy storage',
	'Use as hand luggage or pack in your case',
	'Ideal for overnight stays',
	'Practical & convenient',
	'For an extra bag for travel that’s both durable and stylish, look no further than this foldable and lightweight holdall. Versatile, slimline and strong, it is perfect for overnight stays, weekend breaks and more. Cabin approved as well as convenient to pack, use it as hand luggage or squeeze it into your suitcase and take it on your travels.'
	);
insert into dbo.Products
	([ID],[NameProduct],[Category],[Stock],[CurentPrice],[OldPrice],[SmallPicture],[BigPicture],[Detail1],[Detail2],[Detail3],[Detail4],[Description])
	values
	(
	12,
	'Tote Bag',
	'Bags',
	7,
	36.89,
	36.89,
	(SELECT * FROM OPENROWSET(BULK N'D:\Wantsome\TheProject\99eStuff\ProductImg\SmallImages\12.jpg', SINGLE_BLOB) as Img12),
	(SELECT * FROM OPENROWSET(BULK N'D:\Wantsome\TheProject\99eStuff\ProductImg\BigImages\12.jpg', SINGLE_BLOB) as Img12),
	'Folds in seconds for easy storage',
	'Use as hand luggage or pack in your case',
	'Ideal for shopping trips & excursions',
	'Practical & convenient design',
	'Carry a little extra with this foldaway bag ideal for shopping, day trips and excursions. Designed to be spacious and convenient without weighing you down, it is super light and folds to a fraction of its size for easy storage. Pop it in your suitcase and take it on your travels, or use it as hand luggage'
	);
insert into dbo.Products
	([ID],[NameProduct],[Category],[Stock],[CurentPrice],[OldPrice],[SmallPicture],[BigPicture],[Detail1],[Detail2],[Detail3],[Detail4],[Description])
	values
	(
	13,
	'Cary Closet',
	'Bags',
	12,
	22.45,
	25.45,
	(SELECT * FROM OPENROWSET(BULK N'D:\Wantsome\TheProject\99eStuff\ProductImg\SmallImages\13.jpg', SINGLE_BLOB) as Img13),
	(SELECT * FROM OPENROWSET(BULK N'D:\Wantsome\TheProject\99eStuff\ProductImg\BigImages\13.jpg', SINGLE_BLOB) as Img13),
	'Use folded for carrying 2 suits',
	'Unfold & store full length dresses',
	'Keeps clothes clean & organised',
	'Clear window for quick contents ID',
	'The Carry Closet is a must for any well-organised traveller. It keeps garments clean, fresh and pressed. Suitable for storing shirts, blouses, jackets and more, it can be used in two ways. When folded it can be accessed at either end, ideal for carrying 2 suits. When unfolded it’s the perfect length for storing long dresses or coats. Just as useful for organising clothes at home, the Carry Closet has a clear window for quickly identifying what’s inside.'
	);
insert into dbo.Products
	([ID],[NameProduct],[Category],[Stock],[CurentPrice],[OldPrice],[SmallPicture],[BigPicture],[Detail1],[Detail2],[Detail3],[Detail4],[Description])
	values
	(
	14,
	'Hybrid Travel Pillow',
	'Comforts',
	4,
	7.36,
	7.36,
	(SELECT * FROM OPENROWSET(BULK N'D:\Wantsome\TheProject\99eStuff\ProductImg\SmallImages\14.jpg', SINGLE_BLOB) as Img14),
	(SELECT * FROM OPENROWSET(BULK N'D:\Wantsome\TheProject\99eStuff\ProductImg\BigImages\14.jpg', SINGLE_BLOB) as Img14),
	'Memory foam top neck pillow with inflatable base',
	'Packs down to 1/4 the size for travel (carry pouch included)',
	'Wide pressure-sealed air valve allows for a quick and easy inflate / deflate',
	'Slim back design for upright sleeping comfort',
	'Combining the comfort of memory foam with the convenience of air, this super-handy design packs to palm-size for ultimate ease. The ultra-comfy, plush memory foam top gently moulds to the contours of your head and neck, while the inflatable base provides an instant support boost for a fully personalised fit. The slim back design is ideal for upright sleeping and the easy-to-use air valve makes it simple to adjust and pack away into its carry bag in an instant.'
	);
insert into dbo.Products
	([ID],[NameProduct],[Category],[Stock],[CurentPrice],[OldPrice],[SmallPicture],[BigPicture],[Detail1],[Detail2],[Detail3],[Detail4],[Description])
	values
	(
	15,
	'Travel Blanket',
	'Comforts',
	6,
	12.78,
	12.78,
	(SELECT * FROM OPENROWSET(BULK N'D:\Wantsome\TheProject\99eStuff\ProductImg\SmallImages\15.jpg', SINGLE_BLOB) as Img15),
	(SELECT * FROM OPENROWSET(BULK N'D:\Wantsome\TheProject\99eStuff\ProductImg\BigImages\15.jpg', SINGLE_BLOB) as Img15),
	'Folds or rolls neatly for travel',
	'Soft to the touch',
	'Fleecy & warm',
	'Cosy, lightweight travel blanket',
	'This oh so cosy travel blanket is perfect for wrapping up warm on a chilly airplane. Its soft fleecy construction means it can be rolled or folded to a fraction of its size for quick and easy storage. Squeeze it into your hand luggage or keep it in your car for extra warmth when away from home.'
	);
insert into dbo.Products
	([ID],[NameProduct],[Category],[Stock],[CurentPrice],[OldPrice],[SmallPicture],[BigPicture],[Detail1],[Detail2],[Detail3],[Detail4],[Description])
	values
	(
	16,
	'Silky Eye Mask',
	'Comforts',
	29,
	4.36,
	4.36,
	(SELECT * FROM OPENROWSET(BULK N'D:\Wantsome\TheProject\99eStuff\ProductImg\SmallImages\16.jpg', SINGLE_BLOB) as Img16),
	(SELECT * FROM OPENROWSET(BULK N'D:\Wantsome\TheProject\99eStuff\ProductImg\BigImages\16.jpg', SINGLE_BLOB) as Img16),
	'Effectively blocks out unwanted light',
	'Gently padded with a fleecy lining',
	'Promotes sound sleep, anywhere',
	'Elasticated headband for a comfortable fit',
	'As smooth as silk, this sleep mask is a pleasure to wear. It’s gently cushioned with an elasticated headband for a really comfortable fit. Whether travelling on a brightly lit plane or relaxing in a hotel bedroom, this pretty sleeping mask blocks even harsh light'
	);
insert into dbo.Products
	([ID],[NameProduct],[Category],[Stock],[CurentPrice],[OldPrice],[SmallPicture],[BigPicture],[Detail1],[Detail2],[Detail3],[Detail4],[Description])
	values
	(
	17,
	'Squeezy Bottles',
	'Comforts',
	62,
	1.89,
	1.89,
	(SELECT * FROM OPENROWSET(BULK N'D:\Wantsome\TheProject\99eStuff\ProductImg\SmallImages\17.jpg', SINGLE_BLOB) as Img17),
	(SELECT * FROM OPENROWSET(BULK N'D:\Wantsome\TheProject\99eStuff\ProductImg\BigImages\17.jpg', SINGLE_BLOB) as Img17),
	'Ideal for carrying liquids & gels',
	'Leakproof non-drip cap',
	'Rear suction cup for hands-free dispensing',
	'2 Per pack',
	'Travelling light just got easier with these squeezy cabin bottles. Featuring a leakproof non-drip cap, they are ideal for carrying all of your favourite liquids and gels without fear of spillage. A suction cup on the rear of each travel bottle enables them to attach instantly to any shower screen or tiled area, perfect for dispensing product hands-free.'
	);
insert into dbo.Products
	([ID],[NameProduct],[Category],[Stock],[CurentPrice],[OldPrice],[SmallPicture],[BigPicture],[Detail1],[Detail2],[Detail3],[Detail4],[Description])
	values
	(
	18,
	'Squeezy Bottles',
	'Accessories',
	5,
	14.22,
	18.28,
	(SELECT * FROM OPENROWSET(BULK N'D:\Wantsome\TheProject\99eStuff\ProductImg\SmallImages\18.jpg', SINGLE_BLOB) as Img18),
	(SELECT * FROM OPENROWSET(BULK N'D:\Wantsome\TheProject\99eStuff\ProductImg\BigImages\18.jpg', SINGLE_BLOB) as Img18),
	'Set using any memorable date',
	'Use with birthdays, anniversaries or special occasions',
	'Secure 5 dial design',
	'TSA accepted for travel in America',
	'So, you’ve printed your tickets and packed your passport, but can you remember your combination? Providing luggage security that’s simply unforgettable, this combination lock uses a memorable date such as a birthday or anniversary as its code. TSA accepted for hassle-free travel in America and beyond, the 5 dial design is quick and to set, simple to remember and ultra secure'
	);
insert into dbo.Products
	([ID],[NameProduct],[Category],[Stock],[CurentPrice],[OldPrice],[SmallPicture],[BigPicture],[Detail1],[Detail2],[Detail3],[Detail4],[Description])
	values
	(
	19,
	'Glo Case Id',
	'Accessories',
	18,
	3.56,
	3.56,
	(SELECT * FROM OPENROWSET(BULK N'D:\Wantsome\TheProject\99eStuff\ProductImg\SmallImages\19.jpg', SINGLE_BLOB) as Img19),
	(SELECT * FROM OPENROWSET(BULK N'D:\Wantsome\TheProject\99eStuff\ProductImg\BigImages\19.jpg', SINGLE_BLOB) as Img19),
	'Instant baggage recognition',
	'Conceals personal details',
	'2 Per pack',
	'Always easy to spot',
	'For luggage that’s always easy to spot, look no further than these vibrant bag tags. They make identifying your belongings on busy airport carousels quick and hassle-free, while safely concealing personal contact information inside. Bold, bright and fun, even the plainest suitcase or holdall can enjoy a little extra personality.'
	);
insert into dbo.Products
	([ID],[NameProduct],[Category],[Stock],[CurentPrice],[OldPrice],[SmallPicture],[BigPicture],[Detail1],[Detail2],[Detail3],[Detail4],[Description])
	values
	(
	20,
	'Carry Clip',
	'Accessories',
	14,
	8.12,
	10.00,
	(SELECT * FROM OPENROWSET(BULK N'D:\Wantsome\TheProject\99eStuff\ProductImg\SmallImages\20.jpg', SINGLE_BLOB) as Img20),
	(SELECT * FROM OPENROWSET(BULK N'D:\Wantsome\TheProject\99eStuff\ProductImg\BigImages\20.jpg', SINGLE_BLOB) as Img20),
	'Ideal for jackets & umbrellas',
	'Attaches extra belongings to any bag',
	'Leaves hands free for more enjoyable travel',
	'Strong karabiner clips to most luggage',
	'Ideal for attaching jackets, umbrellas or extra shopping to the outside of any bag or suitcase, this convenient clip strap leaves hands free for more relaxing travel. The strong karabiner is spring loaded and attaches with ease in seconds. Designed to be reliable and secure, the Carry Clip is the easy way to carry more.'
	);