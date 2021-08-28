using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Xml.Serialization;

namespace ChatExpress
{
    class Serializer
    {
        public static void XMLSerial<T>(T[] items, Stream output)
        {
            XmlSerializer xmlSerializer = new XmlSerializer(typeof(T[]));
            TextWriter writer = new StreamWriter(output);
            try
            {
                xmlSerializer.Serialize(writer, items);
            }
            finally
            {
                writer.Close();
            }
        }

        public static T[] XMLDeserial<T>(Stream input)
        {
            
            XmlSerializer xmlSerializer = new XmlSerializer(typeof(T[]));
            T[] items;
           
            items = (T[])xmlSerializer.Deserialize(input);
            return items;
        }  
    }
}
