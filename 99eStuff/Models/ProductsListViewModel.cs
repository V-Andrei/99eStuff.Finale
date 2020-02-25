namespace _99eStuff.Models
{
    public class ProductsListViewModel
    {
        public int ID { get; set; }

        public string NameProduct { get; set; }

        public string Category { get; set; }

        public int Stock { get; set; }

        public double CurrentPrice { get; set; }

        public double OldPrice { get; set; }

        public byte[] SmallPicture { get; set; }

        public byte[] BigPicture { get; set; }

        public string Description { get; set; }

        public string Detail1 { get; set; }

        public string Detail2 { get; set; }

        public string Detail3 { get; set; }

        public string Detail4 { get; set; }
    }
}