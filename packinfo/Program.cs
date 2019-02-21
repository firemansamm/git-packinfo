using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using Ionic.Zlib;

namespace packinfo
{
    class Program
    {

        static byte[] data;
        static int offset = 0;
        static byte[] buf = new byte[2000];
        static int rd;

        static int readInt()
        {
            int ret = 0;
            for (int i = 0; i < 4; i++)
            {
                ret = (ret << 8) | data[offset + i];
            }
            offset += 4;
            return ret;
        }
        
        enum types : byte
        {
            commit = 1,
            tree = 2,
            blob = 3,
            unknown = 6
        }

        static void Main(string[] args)
        {
            if (args.Length != 1)
            {
                Console.WriteLine("usage: packinfo <filename>");
                return;
            }
            string fn = args[0];
            data = File.ReadAllBytes(fn);

            string magic1 = "PACK";
            for(int i = 0; i < 4; i++)
            {
                if(data[offset + i] != magic1[i])
                {
                    Console.WriteLine("invalid file signature (PACK).");
                    return;
                }
            }
            Console.WriteLine("file signature read successfully.");
            offset += 4;

            Console.WriteLine("read version as {0}.", readInt());

            int objCount = readInt();
            Console.WriteLine("this pack contains {0} objects.", objCount);

            Console.WriteLine("next byte: {0}", data[offset]);

            for(int i = 0; i < objCount; i++)
            {
                Console.WriteLine();
                Console.WriteLine("-- object {0} --", i);
                long len;
                types type;
                type = (types)((byte)(data[offset] << 1) >> 5);
                len = (byte)(data[offset] << 4) >> 4;
                if(data[offset] < 128)
                {
                    offset++;
                } else
                {
                    int j = 0;
                    do
                    {
                        j++;
                        int lsh = 7;
                        if (j == 1) lsh = 4;
                        len |= (data[offset + j] & 0x7f) << lsh;
                    } while (data[offset + j] >= 128);
                    offset += (j + 1);
                }
                Console.WriteLine("expected len {0}", len);

                Console.WriteLine("offset is now at {0}, begin reading object.", offset);

                MemoryStream s = new MemoryStream(data, offset, data.Length - offset - 10);
                ZlibStream zs = new ZlibStream(s, CompressionMode.Decompress);

                Array.Clear(buf, 0, 2000);
                try
                {
                   rd = zs.Read(buf, 0, 2000);
                } catch (Exception ex)
                {
                    Console.WriteLine("encountered an exception while inflating: {0}", ex.Message);
                    for(; rd < 2000 && buf[rd] != 0; rd++) { }
                }

                if(rd != len)
                    Console.WriteLine("expected and inflated lengths do not match (expected: {0}, got: {1})", len, rd);

                Console.WriteLine("deflated {0} bytes.", rd);
                Console.WriteLine("{0} {1}", type, rd);

                switch(type)
                {
                    case types.blob:
                        for(int k=0;k<rd;k++)
                        {
                            Console.Write("{0:X} ", buf[k]);
                        }
                        Console.WriteLine();
                        break;
                    case types.commit:
                        string actual = Encoding.ASCII.GetString(buf, 0, rd);
                        Console.WriteLine(actual);
                        break;
                    case types.tree:
                        int ci = 0;
                        string mode, name, sha;
                        while(true)
                        {
                            if (ci >= rd) break;
                            mode = ""; name = ""; sha = "";
                            while (buf[ci] == 0 || buf[ci] == 0x20) { ci++; }
                            while(buf[ci] >= '0' && buf[ci] <= '9')
                            {
                                mode += (char)buf[ci];
                                ci++;
                            }
                            Console.Write("mode: {0}\t", mode);
                            if (buf[ci] != ' ') Console.WriteLine("bad");
                            ci++;
                            while(buf[ci] != 0)
                            {
                                name += (char)buf[ci];
                                ci++;
                            }
                            Console.Write("name: {0}\t\t", name);
                            ci++;
                            sha = BitConverter.ToString(buf, ci, 20).Replace("-", "").ToLower();
                            Console.WriteLine("sha: {0}", sha);
                            ci += 20;
                        }
                        break;
                    default:
                        Console.WriteLine(BitConverter.ToString(buf, 0, rd).Replace("-", "").ToLower());
                        break;
                }
                

                

                Console.WriteLine("searching for next object...");
                uint cs = Adler.Adler32(1, buf, 0, rd);
                Console.WriteLine("checksum of previous object = {0:X}", cs);

                
                for (; offset < data.Length - 4; offset++) 
                {
                    if(data[offset - 4] == ((cs & 0xff000000) >> 24) && data[offset - 3] == ((cs & 0x00ff0000) >> 16) 
                        && data[offset - 2] == ((cs & 0x0000ff00) >> 8) && data[offset - 1] == ((cs & 0x000000ff)))
                    {
                        Console.WriteLine("found good checksum at offset {0}!", offset - 4);
                        break;
                    }
                }
                Console.WriteLine("next object header is most likely to be {0}.", offset);

                Console.WriteLine("-- end object {0} --", i);
            }

            Console.WriteLine("{0} bytes remain.", data.Length - offset);
            if (data.Length - offset != 20) Console.WriteLine("this is not enough space for a sha1 - is your object corrupt?");

            SHA1Managed hash = new SHA1Managed();
            byte[] hashed = hash.ComputeHash(data, 0, offset);
            Console.WriteLine("computed hash: {0}", BitConverter.ToString(hashed).Replace("-", "").ToLower());
            Console.WriteLine("found hash: {0}", BitConverter.ToString(data, offset, 20).Replace("-", "").ToLower());

            // check values
            bool ok = true;
            for(int i = 0; i < 20; i++)
            {
                ok &= (data[offset + i] == hashed[i]);
            }
            if (!ok) Console.WriteLine("bad hash: hash does not match expected value.");
            else Console.WriteLine("hash checks out.");

            Console.WriteLine("done, press enter to exit.");
            Console.ReadLine();
        }
    }
}
