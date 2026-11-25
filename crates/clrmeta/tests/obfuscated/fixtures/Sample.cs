using System;
using System.Collections.Generic;

namespace Fixture
{
    public interface IShape { double Area(); }

    public sealed class Circle : IShape
    {
        private readonly double radius;
        public Circle(double radius) { this.radius = radius; }
        public double Area() { return Math.PI * radius * radius; }
        public class Unit : IShape { public double Area() { return 1.0; } }
    }

    public enum Color { Red = 1, Green = 2 }

    public static class Program
    {
        public static T First<T>(IList<T> items) { return items[0]; }

        public static int Divide(int a, int b)
        {
            try { return a / b; }
            catch (DivideByZeroException) { return -1; }
            finally { Console.Write(""); }
        }

        public static int Main(string[] args)
        {
            var shapes = new List<IShape> { new Circle(2.0), new Circle.Unit() };
            double total = 0;
            foreach (var shape in shapes) total += shape.Area();
            int checksum = (int)total + Divide(10, 0) + Divide(9, 3) + (int)First(new[] { Color.Green });
            Console.WriteLine("checksum " + checksum);
            Console.WriteLine("type " + typeof(Circle).Name);
            Console.WriteLine("constant " + typeof(Color).GetField("Green").GetRawConstantValue());
            Console.WriteLine("mvid " + typeof(Program).Module.ModuleVersionId);
            byte[] key = typeof(Program).Assembly.GetName().GetPublicKey();
            Console.WriteLine("key " + (key == null ? -1 : key.Length));
            return checksum == 17 ? 0 : 1;
        }
    }
}
