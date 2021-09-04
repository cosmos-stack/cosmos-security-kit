using System;
using System.Text;
using Cosmos.Security.Verification;
using Cosmos.Text;
using EnumsNET;

// ReSharper disable InconsistentNaming

namespace Cosmos.Validation.Registrars
{
    public static class VerifyMDRegistrarExtensions
    {
        #region Common entry

        public static IPredicateValidationRegistrar VerifyMessageDigest(this IValueFluentValidationRegistrar registrar, string hexVal, MdTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyMessageDigest(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar VerifyMessageDigest(this IValueFluentValidationRegistrar registrar, string hexVal, MdTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(MdHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValidationRegistrar VerifyMessageDigest(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, MdTypes type)
        {
            return registrar.VerifyMessageDigest(checker, type, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar VerifyMessageDigest(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, MdTypes type, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(MdHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T> VerifyMessageDigest<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, MdTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyMessageDigest<T>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T> VerifyMessageDigest<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, MdTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(MdHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T> VerifyMessageDigest<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, MdTypes type)
        {
            return registrar.VerifyMessageDigest<T>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T> VerifyMessageDigest<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, MdTypes type, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(MdHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMessageDigest<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, MdTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyMessageDigest<T, TVal>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMessageDigest<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, MdTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(MdHandler.Verify<TVal>()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMessageDigest<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, MdTypes type)
        {
            return registrar.VerifyMessageDigest<T, TVal>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMessageDigest<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, MdTypes type, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(MdHandler.CustomVerify<TVal>()(type)(encoding)(checker)(type.GetName()));
        }

        #endregion

        #region VerifyMD2

        public static IPredicateValidationRegistrar VerifyMD2(this IValueFluentValidationRegistrar registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyMD2(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar VerifyMD2(this IValueFluentValidationRegistrar registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(MdHandler.Verify()(hexVal)(MdTypes.Md2)(encoding)(ignoreCase)("MD2"));
        }

        public static IPredicateValidationRegistrar VerifyMD2(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker)
        {
            return registrar.VerifyMD2(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar VerifyMD2(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(MdHandler.CustomVerify()(MdTypes.Md2)(encoding)(checker)("MD2"));
        }

        public static IPredicateValidationRegistrar<T> VerifyMD2<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyMD2<T>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T> VerifyMD2<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(MdHandler.Verify()(hexVal)(MdTypes.Md2)(encoding)(ignoreCase)("MD2"));
        }

        public static IPredicateValidationRegistrar<T> VerifyMD2<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker)
        {
            return registrar.VerifyMD2<T>(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T> VerifyMD2<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(MdHandler.CustomVerify()(MdTypes.Md2)(encoding)(checker)("MD2"));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMD2<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyMD2<T, TVal>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMD2<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(MdHandler.Verify<TVal>()(hexVal)(MdTypes.Md2)(encoding)(ignoreCase)("MD2"));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMD2<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker)
        {
            return registrar.VerifyMD2<T, TVal>(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMD2<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(MdHandler.CustomVerify<TVal>()(MdTypes.Md2)(encoding)(checker)("MD2"));
        }

        #endregion

        #region VerifyMD4

        public static IPredicateValidationRegistrar VerifyMD4(this IValueFluentValidationRegistrar registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyMD4(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar VerifyMD4(this IValueFluentValidationRegistrar registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(MdHandler.Verify()(hexVal)(MdTypes.Md4)(encoding)(ignoreCase)("MD4"));
        }

        public static IPredicateValidationRegistrar VerifyMD4(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker)
        {
            return registrar.VerifyMD4(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar VerifyMD4(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(MdHandler.CustomVerify()(MdTypes.Md4)(encoding)(checker)("MD4"));
        }

        public static IPredicateValidationRegistrar<T> VerifyMD4<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyMD4<T>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T> VerifyMD4<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(MdHandler.Verify()(hexVal)(MdTypes.Md4)(encoding)(ignoreCase)("MD4"));
        }

        public static IPredicateValidationRegistrar<T> VerifyMD4<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker)
        {
            return registrar.VerifyMD4<T>(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T> VerifyMD4<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(MdHandler.CustomVerify()(MdTypes.Md4)(encoding)(checker)("MD4"));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMD4<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyMD4<T, TVal>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMD4<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(MdHandler.Verify<TVal>()(hexVal)(MdTypes.Md4)(encoding)(ignoreCase)("MD4"));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMD4<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker)
        {
            return registrar.VerifyMD4<T, TVal>(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMD4<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(MdHandler.CustomVerify<TVal>()(MdTypes.Md4)(encoding)(checker)("MD4"));
        }

        #endregion

        #region VerifyMD5

        public static IPredicateValidationRegistrar VerifyMD5(this IValueFluentValidationRegistrar registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyMD5(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar VerifyMD5(this IValueFluentValidationRegistrar registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(MdHandler.Verify()(hexVal)(MdTypes.Md5)(encoding)(ignoreCase)("MD5"));
        }

        public static IPredicateValidationRegistrar VerifyMD5(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker)
        {
            return registrar.VerifyMD5(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar VerifyMD5(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(MdHandler.CustomVerify()(MdTypes.Md5)(encoding)(checker)("MD5"));
        }

        public static IPredicateValidationRegistrar<T> VerifyMD5<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyMD5<T>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T> VerifyMD5<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(MdHandler.Verify()(hexVal)(MdTypes.Md5)(encoding)(ignoreCase)("MD5"));
        }

        public static IPredicateValidationRegistrar<T> VerifyMD5<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker)
        {
            return registrar.VerifyMD5<T>(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T> VerifyMD5<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(MdHandler.CustomVerify()(MdTypes.Md5)(encoding)(checker)("MD5"));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMD5<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyMD5<T, TVal>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMD5<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(MdHandler.Verify<TVal>()(hexVal)(MdTypes.Md5)(encoding)(ignoreCase)("MD5"));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMD5<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker)
        {
            return registrar.VerifyMD5<T, TVal>(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMD5<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(MdHandler.CustomVerify<TVal>()(MdTypes.Md5)(encoding)(checker)("MD5"));
        }

        #endregion

        #region VerifyMD6

        public static IPredicateValidationRegistrar VerifyMD6(this IValueFluentValidationRegistrar registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyMD6(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar VerifyMD6(this IValueFluentValidationRegistrar registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(MdHandler.Verify()(hexVal)(MdTypes.Md6)(encoding)(ignoreCase)("MD6"));
        }

        public static IPredicateValidationRegistrar VerifyMD6(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker)
        {
            return registrar.VerifyMD6(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar VerifyMD6(this IValueFluentValidationRegistrar registrar, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(MdHandler.CustomVerify()(MdTypes.Md6)(encoding)(checker)("MD6"));
        }

        public static IPredicateValidationRegistrar<T> VerifyMD6<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyMD6<T>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T> VerifyMD6<T>(this IValueFluentValidationRegistrar<T> registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(MdHandler.Verify()(hexVal)(MdTypes.Md6)(encoding)(ignoreCase)("MD6"));
        }

        public static IPredicateValidationRegistrar<T> VerifyMD6<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker)
        {
            return registrar.VerifyMD6<T>(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T> VerifyMD6<T>(this IValueFluentValidationRegistrar<T> registrar, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(MdHandler.CustomVerify()(MdTypes.Md6)(encoding)(checker)("MD6"));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMD6<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return registrar.VerifyMD6<T, TVal>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMD6<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));
            return registrar.Func(MdHandler.Verify<TVal>()(hexVal)(MdTypes.Md6)(encoding)(ignoreCase)("MD6"));
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMD6<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker)
        {
            return registrar.VerifyMD6<T, TVal>(checker, Encoding.UTF8);
        }

        public static IPredicateValidationRegistrar<T, TVal> VerifyMD6<T, TVal>(this IValueFluentValidationRegistrar<T, TVal> registrar, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (registrar is null)
                throw new ArgumentNullException(nameof(registrar));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return registrar.Func(MdHandler.CustomVerify<TVal>()(MdTypes.Md6)(encoding)(checker)("MD6"));
        }

        #endregion
    }
}