using System;
using System.Collections.Generic;
using System.Data;
using System.Web.Mvc;
using _99eStuff.Data;
using _99eStuff.Models;

namespace _99eStuff.Controllers
{
    public class HomeController : Controller
    {
        ConnectionData connectionData = new ConnectionData();
        DataTable dt;
     
        public ActionResult About()
        {
            return View();
        }

        public ActionResult Contact()
        {
            return View();
        }

        public ActionResult Shop()
        {
            return ProductAndDetailed();
        }

        public ActionResult Index()
        {
            return ProductAndDetailed();
        }
        private ActionResult ProductAndDetailed()
        {
            string mycmd = "select * from Products";
            dt = new DataTable();

            dt = connectionData.GetAll(mycmd);


            List<ProductsListViewModel> list = new List<ProductsListViewModel>();

            for (int i = 0; i < dt.Rows.Count; i++)
            {
                ProductsListViewModel prod = new ProductsListViewModel
                {
                    ID = Convert.ToInt32(dt.Rows[i]["ID"]),
                    NameProduct = dt.Rows[i]["NameProduct"].ToString(),
                    Category = dt.Rows[i]["Category"].ToString(),
                    Stock = Convert.ToInt32(dt.Rows[i]["Stock"]),
                    OldPrice = Convert.ToDouble(dt.Rows[i]["OldPrice"]),
                    CurrentPrice = Convert.ToDouble(dt.Rows[i]["CurentPrice"]),
                    Description = dt.Rows[i]["Description"].ToString(),
                    Detail1 = dt.Rows[i]["Detail1"].ToString(),
                    Detail2 = dt.Rows[i]["Detail2"].ToString(),
                    Detail3 = dt.Rows[i]["Detail3"].ToString(),
                    Detail4 = dt.Rows[i]["Detail4"].ToString(),
                    SmallPicture = (byte[])(dt.Rows[i]["SmallPicture"]),
                    BigPicture = (byte[])(dt.Rows[i]["BigPicture"])
                };

                list.Add(prod);
            }


            return View(list);
        }

    }
}