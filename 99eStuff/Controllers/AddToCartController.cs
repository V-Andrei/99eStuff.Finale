using _99eStuff.Data;
using _99eStuff.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Mvc;

namespace _99eStuff.Controllers
{
    public class AddToCartController : Controller
    {
        ConnectionData connectionData = new ConnectionData();
   
        public ActionResult Add(ProductsCartViewModel prod)
        {

            if (Session["cart"] == null)
            {
                List<ProductsCartViewModel> li = new List<ProductsCartViewModel>();

                li.Add(prod);
                Session["cart"] = li;
                ViewBag.cart = li.Count();
                Session["count"] = 1;
            }
            else
            {
                List<ProductsCartViewModel> li = (List<ProductsCartViewModel>)Session["cart"];
                li.Add(prod);
                Session["cart"] = li;
                ViewBag.cart = li.Count();
                Session["count"] = Convert.ToInt32(Session["count"]) + 1;

            }
            return RedirectToAction("Shop", "Home");


        }

        public ActionResult Cart()
        {

            return View((List<ProductsCartViewModel>)Session["cart"]);

        }
        public ActionResult EmptyCart()
        {
            return View();
        }

        public ActionResult Remove(ProductsCartViewModel prod)
        {
            List<ProductsCartViewModel> li = (List<ProductsCartViewModel>)Session["cart"];
            li.RemoveAll(x => x.ID == prod.ID);
            Session["cart"] = li;
            Session["count"] = Convert.ToInt32(Session["count"]) - 1;
            return RedirectToAction("Cart", "AddToCart");
        }

        public ActionResult Checkout()
        {
            return View();
        }

        public ActionResult CheckoutEnd()
        {
            Session.Abandon();
            return RedirectToAction("Checkout", "AddToCart");
        }

    }
}