using System;
using System.Text;
using Cosmos.Security.Verification;
using Cosmos.Text;
using EnumsNET;

// ReSharper disable InconsistentNaming

namespace Cosmos.Validation
{
    public static class VerifyMDExtensions
    {
        #region Common entry

        public static IPredicateValueRuleBuilder VerifyMessageDigest(this IValueRuleBuilder builder, string hexVal, MdTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyMessageDigest(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder VerifyMessageDigest(this IValueRuleBuilder builder, string hexVal, MdTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(MdHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder VerifyMessageDigest(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, MdTypes type)
        {
            return builder.VerifyMessageDigest(checker, type, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder VerifyMessageDigest(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, MdTypes type, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(MdHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }
        
        public static IPredicateValueRuleBuilder<T> VerifyMessageDigest<T>(this IValueRuleBuilder<T> builder, string hexVal, MdTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyMessageDigest<T>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T> VerifyMessageDigest<T>(this IValueRuleBuilder<T> builder, string hexVal, MdTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(MdHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T> VerifyMessageDigest<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, MdTypes type)
        {
            return builder.VerifyMessageDigest<T>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T> VerifyMessageDigest<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, MdTypes type, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(MdHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }
        
        public static IPredicateValueRuleBuilder<T, TVal> VerifyMessageDigest<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, MdTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyMessageDigest<T, TVal>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyMessageDigest<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, MdTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(MdHandler.Verify<TVal>()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyMessageDigest<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, MdTypes type)
        {
            return builder.VerifyMessageDigest<T, TVal>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyMessageDigest<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, MdTypes type, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(MdHandler.CustomVerify<TVal>()(type)(encoding)(checker)(type.GetName()));
        }

        #endregion

        #region VerifyMD2

        public static IPredicateValueRuleBuilder VerifyMD2(this IValueRuleBuilder builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyMD2(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder VerifyMD2(this IValueRuleBuilder builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(MdHandler.Verify()(hexVal)(MdTypes.Md2)(encoding)(ignoreCase)("MD2"));
        }

        public static IPredicateValueRuleBuilder VerifyMD2(this IValueRuleBuilder builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifyMD2(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder VerifyMD2(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(MdHandler.CustomVerify()(MdTypes.Md2)(encoding)(checker)("MD2"));
        }
        
        public static IPredicateValueRuleBuilder<T> VerifyMD2<T>(this IValueRuleBuilder<T> builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyMD2<T>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T> VerifyMD2<T>(this IValueRuleBuilder<T> builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(MdHandler.Verify()(hexVal)(MdTypes.Md2)(encoding)(ignoreCase)("MD2"));
        }

        public static IPredicateValueRuleBuilder<T> VerifyMD2<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifyMD2<T>(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T> VerifyMD2<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(MdHandler.CustomVerify()(MdTypes.Md2)(encoding)(checker)("MD2"));
        }
        
        public static IPredicateValueRuleBuilder<T, TVal> VerifyMD2<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyMD2<T, TVal>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyMD2<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(MdHandler.Verify<TVal>()(hexVal)(MdTypes.Md2)(encoding)(ignoreCase)("MD2"));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyMD2<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifyMD2<T, TVal>(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyMD2<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(MdHandler.CustomVerify<TVal>()(MdTypes.Md2)(encoding)(checker)("MD2"));
        }

        #endregion

        #region VerifyMD4

        public static IPredicateValueRuleBuilder VerifyMD4(this IValueRuleBuilder builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyMD4(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder VerifyMD4(this IValueRuleBuilder builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(MdHandler.Verify()(hexVal)(MdTypes.Md4)(encoding)(ignoreCase)("MD4"));
        }

        public static IPredicateValueRuleBuilder VerifyMD4(this IValueRuleBuilder builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifyMD4(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder VerifyMD4(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(MdHandler.CustomVerify()(MdTypes.Md4)(encoding)(checker)("MD4"));
        }
        
        public static IPredicateValueRuleBuilder<T> VerifyMD4<T>(this IValueRuleBuilder<T> builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyMD4<T>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T> VerifyMD4<T>(this IValueRuleBuilder<T> builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(MdHandler.Verify()(hexVal)(MdTypes.Md4)(encoding)(ignoreCase)("MD4"));
        }

        public static IPredicateValueRuleBuilder<T> VerifyMD4<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifyMD4<T>(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T> VerifyMD4<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(MdHandler.CustomVerify()(MdTypes.Md4)(encoding)(checker)("MD4"));
        }
        
        public static IPredicateValueRuleBuilder<T, TVal> VerifyMD4<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyMD4<T, TVal>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyMD4<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(MdHandler.Verify<TVal>()(hexVal)(MdTypes.Md4)(encoding)(ignoreCase)("MD4"));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyMD4<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifyMD4<T, TVal>(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyMD4<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(MdHandler.CustomVerify<TVal>()(MdTypes.Md4)(encoding)(checker)("MD4"));
        }

        #endregion

        #region VerifyMD5

        public static IPredicateValueRuleBuilder VerifyMD5(this IValueRuleBuilder builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyMD5(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder VerifyMD5(this IValueRuleBuilder builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(MdHandler.Verify()(hexVal)(MdTypes.Md5)(encoding)(ignoreCase)("MD5"));
        }

        public static IPredicateValueRuleBuilder VerifyMD5(this IValueRuleBuilder builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifyMD5(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder VerifyMD5(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(MdHandler.CustomVerify()(MdTypes.Md5)(encoding)(checker)("MD5"));
        }
        
        public static IPredicateValueRuleBuilder<T> VerifyMD5<T>(this IValueRuleBuilder<T> builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyMD5<T>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T> VerifyMD5<T>(this IValueRuleBuilder<T> builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(MdHandler.Verify()(hexVal)(MdTypes.Md5)(encoding)(ignoreCase)("MD5"));
        }

        public static IPredicateValueRuleBuilder<T> VerifyMD5<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifyMD5<T>(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T> VerifyMD5<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(MdHandler.CustomVerify()(MdTypes.Md5)(encoding)(checker)("MD5"));
        }
        
        public static IPredicateValueRuleBuilder<T, TVal> VerifyMD5<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyMD5<T, TVal>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyMD5<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(MdHandler.Verify<TVal>()(hexVal)(MdTypes.Md5)(encoding)(ignoreCase)("MD5"));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyMD5<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifyMD5<T, TVal>(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyMD5<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(MdHandler.CustomVerify<TVal>()(MdTypes.Md5)(encoding)(checker)("MD5"));
        }

        #endregion

        #region VerifyMD6

        public static IPredicateValueRuleBuilder VerifyMD6(this IValueRuleBuilder builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyMD6(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder VerifyMD6(this IValueRuleBuilder builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(MdHandler.Verify()(hexVal)(MdTypes.Md6)(encoding)(ignoreCase)("MD6"));
        }

        public static IPredicateValueRuleBuilder VerifyMD6(this IValueRuleBuilder builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifyMD6(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder VerifyMD6(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(MdHandler.CustomVerify()(MdTypes.Md6)(encoding)(checker)("MD6"));
        }
        
        public static IPredicateValueRuleBuilder<T> VerifyMD6<T>(this IValueRuleBuilder<T> builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyMD6<T>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T> VerifyMD6<T>(this IValueRuleBuilder<T> builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(MdHandler.Verify()(hexVal)(MdTypes.Md6)(encoding)(ignoreCase)("MD6"));
        }

        public static IPredicateValueRuleBuilder<T> VerifyMD6<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifyMD6<T>(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T> VerifyMD6<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(MdHandler.CustomVerify()(MdTypes.Md6)(encoding)(checker)("MD6"));
        }
        
        public static IPredicateValueRuleBuilder<T, TVal> VerifyMD6<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyMD6<T, TVal>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyMD6<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(MdHandler.Verify<TVal>()(hexVal)(MdTypes.Md6)(encoding)(ignoreCase)("MD6"));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyMD6<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifyMD6<T, TVal>(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyMD6<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(MdHandler.CustomVerify<TVal>()(MdTypes.Md6)(encoding)(checker)("MD6"));
        }

        #endregion
    }
}