using System;
using System.Text;
using Cosmos.Security.Verification;
using Cosmos.Text;
using EnumsNET;
// ReSharper disable InconsistentNaming

namespace Cosmos.Validation
{
    public static class VerifySHAExtensions
    {
        #region Common Entry

        public static IPredicateValueRuleBuilder VerifySHA(this IValueRuleBuilder builder, string hexVal, ShaTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifySHA(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder VerifySHA(this IValueRuleBuilder builder, string hexVal, ShaTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(ShaHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder VerifySHA(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, ShaTypes type)
        {
            return builder.VerifySHA(checker, type, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder VerifySHA(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, ShaTypes type, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(ShaHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T> VerifySHA<T>(this IValueRuleBuilder<T> builder, string hexVal, ShaTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifySHA<T>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T> VerifySHA<T>(this IValueRuleBuilder<T> builder, string hexVal, ShaTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(ShaHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T> VerifySHA<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, ShaTypes type)
        {
            return builder.VerifySHA<T>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T> VerifySHA<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, ShaTypes type, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(ShaHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifySHA<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, ShaTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifySHA<T, TVal>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifySHA<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, ShaTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(ShaHandler.Verify<TVal>()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifySHA<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, ShaTypes type)
        {
            return builder.VerifySHA<T, TVal>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifySHA<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, ShaTypes type, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(ShaHandler.CustomVerify<TVal>()(type)(encoding)(checker)(type.GetName()));
        }

        #endregion

        #region VerifySHA1

        public static IPredicateValueRuleBuilder VerifySHA1(this IValueRuleBuilder builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifySHA1(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder VerifySHA1(this IValueRuleBuilder builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(ShaHandler.Verify()(hexVal)(ShaTypes.Sha1)(encoding)(ignoreCase)("SHA-1"));
        }

        public static IPredicateValueRuleBuilder VerifySHA1(this IValueRuleBuilder builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifySHA1(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder VerifySHA1(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(ShaHandler.CustomVerify()(ShaTypes.Sha1)(encoding)(checker)("SHA-1"));
        }

        public static IPredicateValueRuleBuilder<T> VerifySHA1<T>(this IValueRuleBuilder<T> builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifySHA1<T>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T> VerifySHA1<T>(this IValueRuleBuilder<T> builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(ShaHandler.Verify()(hexVal)(ShaTypes.Sha1)(encoding)(ignoreCase)("SHA-1"));
        }

        public static IPredicateValueRuleBuilder<T> VerifySHA1<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifySHA1<T>(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T> VerifySHA1<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(ShaHandler.CustomVerify()(ShaTypes.Sha1)(encoding)(checker)("SHA-1"));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifySHA1<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifySHA1<T, TVal>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifySHA1<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(ShaHandler.Verify<TVal>()(hexVal)(ShaTypes.Sha1)(encoding)(ignoreCase)("SHA-1"));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifySHA1<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifySHA1<T, TVal>(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifySHA1<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(ShaHandler.CustomVerify<TVal>()(ShaTypes.Sha1)(encoding)(checker)("SHA-1"));
        }

        #endregion

        #region VerifySHA2/224

        public static IPredicateValueRuleBuilder VerifySHA224(this IValueRuleBuilder builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifySHA224(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder VerifySHA224(this IValueRuleBuilder builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(ShaHandler.Verify()(hexVal)(ShaTypes.Sha224)(encoding)(ignoreCase)("SHA-2/224"));
        }

        public static IPredicateValueRuleBuilder VerifySHA224(this IValueRuleBuilder builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifySHA224(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder VerifySHA224(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(ShaHandler.CustomVerify()(ShaTypes.Sha224)(encoding)(checker)("SHA-2/224"));
        }

        public static IPredicateValueRuleBuilder<T> VerifySHA224<T>(this IValueRuleBuilder<T> builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifySHA224<T>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T> VerifySHA224<T>(this IValueRuleBuilder<T> builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(ShaHandler.Verify()(hexVal)(ShaTypes.Sha224)(encoding)(ignoreCase)("SHA-2/224"));
        }

        public static IPredicateValueRuleBuilder<T> VerifySHA224<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifySHA224<T>(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T> VerifySHA224<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(ShaHandler.CustomVerify()(ShaTypes.Sha224)(encoding)(checker)("SHA-2/224"));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifySHA224<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifySHA224(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifySHA224<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(ShaHandler.Verify<TVal>()(hexVal)(ShaTypes.Sha224)(encoding)(ignoreCase)("SHA-2/224"));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifySHA224<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifySHA224(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifySHA224<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(ShaHandler.CustomVerify<TVal>()(ShaTypes.Sha224)(encoding)(checker)("SHA-2/224"));
        }

        #endregion

        #region VerifySHA2/256

        public static IPredicateValueRuleBuilder VerifySHA256(this IValueRuleBuilder builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifySHA256(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder VerifySHA256(this IValueRuleBuilder builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(ShaHandler.Verify()(hexVal)(ShaTypes.Sha256)(encoding)(ignoreCase)("SHA-2/256"));
        }

        public static IPredicateValueRuleBuilder VerifySHA256(this IValueRuleBuilder builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifySHA256(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder VerifySHA256(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(ShaHandler.CustomVerify()(ShaTypes.Sha256)(encoding)(checker)("SHA-2/256"));
        }

        public static IPredicateValueRuleBuilder<T> VerifySHA256<T>(this IValueRuleBuilder<T> builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifySHA256<T>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T> VerifySHA256<T>(this IValueRuleBuilder<T> builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(ShaHandler.Verify()(hexVal)(ShaTypes.Sha256)(encoding)(ignoreCase)("SHA-2/256"));
        }

        public static IPredicateValueRuleBuilder<T> VerifySHA256<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifySHA256<T>(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T> VerifySHA256<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(ShaHandler.CustomVerify()(ShaTypes.Sha256)(encoding)(checker)("SHA-2/256"));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifySHA256<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifySHA256(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifySHA256<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(ShaHandler.Verify<TVal>()(hexVal)(ShaTypes.Sha256)(encoding)(ignoreCase)("SHA-2/256"));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifySHA256<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifySHA256(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifySHA256<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(ShaHandler.CustomVerify<TVal>()(ShaTypes.Sha256)(encoding)(checker)("SHA-2/256"));
        }

        #endregion

        #region VerifySHA2/384

        public static IPredicateValueRuleBuilder VerifySHA384(this IValueRuleBuilder builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifySHA384(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder VerifySHA384(this IValueRuleBuilder builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(ShaHandler.Verify()(hexVal)(ShaTypes.Sha384)(encoding)(ignoreCase)("SHA-2/384"));
        }

        public static IPredicateValueRuleBuilder VerifySHA384(this IValueRuleBuilder builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifySHA384(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder VerifySHA384(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(ShaHandler.CustomVerify()(ShaTypes.Sha384)(encoding)(checker)("SHA-2/384"));
        }

        public static IPredicateValueRuleBuilder<T> VerifySHA384<T>(this IValueRuleBuilder<T> builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifySHA384<T>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T> VerifySHA384<T>(this IValueRuleBuilder<T> builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(ShaHandler.Verify()(hexVal)(ShaTypes.Sha384)(encoding)(ignoreCase)("SHA-2/384"));
        }

        public static IPredicateValueRuleBuilder<T> VerifySHA384<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifySHA384<T>(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T> VerifySHA384<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(ShaHandler.CustomVerify()(ShaTypes.Sha384)(encoding)(checker)("SHA-2/384"));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifySHA384<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifySHA384<T, TVal>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifySHA384<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(ShaHandler.Verify<TVal>()(hexVal)(ShaTypes.Sha384)(encoding)(ignoreCase)("SHA-2/384"));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifySHA384<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifySHA384<T, TVal>(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifySHA384<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(ShaHandler.CustomVerify<TVal>()(ShaTypes.Sha384)(encoding)(checker)("SHA-2/384"));
        }

        #endregion

        #region VerifySHA2/512

        public static IPredicateValueRuleBuilder VerifySHA512(this IValueRuleBuilder builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifySHA512(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder VerifySHA512(this IValueRuleBuilder builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(ShaHandler.Verify()(hexVal)(ShaTypes.Sha512)(encoding)(ignoreCase)("SHA-2/512"));
        }

        public static IPredicateValueRuleBuilder VerifySHA512(this IValueRuleBuilder builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifySHA512(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder VerifySHA512(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(ShaHandler.CustomVerify()(ShaTypes.Sha512)(encoding)(checker)("SHA-2/512"));
        }

        public static IPredicateValueRuleBuilder<T> VerifySHA512<T>(this IValueRuleBuilder<T> builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifySHA512<T>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T> VerifySHA512<T>(this IValueRuleBuilder<T> builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(ShaHandler.Verify()(hexVal)(ShaTypes.Sha512)(encoding)(ignoreCase)("SHA-2/512"));
        }

        public static IPredicateValueRuleBuilder<T> VerifySHA512<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifySHA512<T>(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T> VerifySHA512<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(ShaHandler.CustomVerify()(ShaTypes.Sha512)(encoding)(checker)("SHA-2/512"));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifySHA512<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifySHA512<T, TVal>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifySHA512<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(ShaHandler.Verify<TVal>()(hexVal)(ShaTypes.Sha512)(encoding)(ignoreCase)("SHA-2/512"));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifySHA512<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifySHA512<T, TVal>(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifySHA512<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(ShaHandler.CustomVerify<TVal>()(ShaTypes.Sha512)(encoding)(checker)("SHA-2/512"));
        }

        #endregion
    }
}