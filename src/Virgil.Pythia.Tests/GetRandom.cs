namespace Virgil.Pythia.Tests
{
    using System;
    
    public class GetRandom
    {
        public static byte[] Bytes(int size = 32) 
        {
            Random rnd = new Random();
            Byte[] b = new Byte[size];

            rnd.NextBytes(b);
            return b;
        }
    }
}
