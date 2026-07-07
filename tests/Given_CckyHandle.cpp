#include <functional>
#include <utility>

#include <gtest/gtest.h>

#include "CckyTest.h"
#include "crypto/CckyException.h"
#include "crypto/CckyHandle.h"

class Given_CckyHandle : public CckyTest
{
  protected:
    static inline std::function<void(int)> s_deleter;
    static inline std::function<int(int)> s_copier;
    static inline std::function<bool(int)> s_isInvalid;

    void SetUp() override
    {
        CckyTest::SetUp();
        s_deleter = [](int) {};
        s_copier = [](int h) { return h; };
        s_isInvalid = [](int h) { return h == 0; };
    }

  public:
    static void forwardDeleter(int h)
    {
        if (s_deleter)
        {
            s_deleter(h);
        }
    }

    static inline std::function<void(int, int, bool)> s_tupleDeleter;
    static void forwardTupleDeleter(int h, int a, bool b)
    {
        if (s_tupleDeleter)
        {
            s_tupleDeleter(h, a, b);
        }
    }

    static int forwardCopier(int h) { return s_copier ? s_copier(h) : h; }

    static bool forwardIsInvalid(int h) { return s_isInvalid ? s_isInvalid(h) : (h == 0); }
};

using TestHandle = ccky::crypto::CckyHandle<int, Given_CckyHandle::forwardDeleter,
    ccky::crypto::CckyDefault{}, ccky::crypto::CckyNoCopy{}, Given_CckyHandle::forwardIsInvalid>;

using CopyableTestHandle =
    ccky::crypto::CckyHandle<int, Given_CckyHandle::forwardDeleter, ccky::crypto::CckyDefault{},
        Given_CckyHandle::forwardCopier, Given_CckyHandle::forwardIsInvalid>;

using TupleTestHandle = ccky::crypto::CckyHandle<int, Given_CckyHandle::forwardTupleDeleter,
    std::pair<int, bool>{100, true}, ccky::crypto::CckyNoCopy{},
    Given_CckyHandle::forwardIsInvalid>;

struct DummyPointed
{
    int val;
};

using PointerTestHandle = ccky::crypto::CckyHandle<DummyPointed*, [](DummyPointed*) {},
    ccky::crypto::CckyDefault{}, ccky::crypto::CckyNoCopy{}, ccky::crypto::CckyDefault{}>;

TEST_F(Given_CckyHandle, When_ConstructedWithValidValue_IsValidAndGetReturnsValue)
{
    TestHandle handle(42);

    bool valid = handle.isValid();
    int val = handle.get();

    EXPECT_TRUE(valid);
    EXPECT_EQ(val, 42);
}

TEST_F(Given_CckyHandle, When_ConstructedDefaultOrZero_IsInvalid)
{
    TestHandle handle;

    bool valid = handle.isValid();
    int val = handle.get();

    EXPECT_FALSE(valid);
    EXPECT_EQ(val, 0);
}

TEST_F(Given_CckyHandle, When_DestroyedValidHandle_CallsDeleter)
{
    bool deleterCalled = false;
    int deletedVal = -1;
    s_deleter = [&](int h)
    {
        deleterCalled = true;
        deletedVal = h;
    };

    {
        TestHandle handle(42);
    }

    EXPECT_TRUE(deleterCalled);
    EXPECT_EQ(deletedVal, 42);
}

TEST_F(Given_CckyHandle, When_DestroyedInvalidHandle_DoesNotCallDeleter)
{
    bool deleterCalled = false;
    s_deleter = [&](int) { deleterCalled = true; };

    {
        TestHandle handle(0);
    }

    EXPECT_FALSE(deleterCalled);
}

TEST_F(Given_CckyHandle, When_MoveConstructed_TransfersOwnershipAndResetsSource)
{
    TestHandle source(42);

    TestHandle target(std::move(source));

    EXPECT_TRUE(target.isValid());
    EXPECT_EQ(target.get(), 42);
    EXPECT_FALSE(source.isValid());
    EXPECT_EQ(source.get(), 0);
}

TEST_F(Given_CckyHandle, When_MoveAssigned_ReleasesExistingAndTransfersOwnership)
{
    bool deleterCalled = false;
    int deletedVal = -1;
    s_deleter = [&](int h)
    {
        deleterCalled = true;
        deletedVal = h;
    };
    TestHandle source(99);
    TestHandle target(42);

    target = std::move(source);

    EXPECT_TRUE(deleterCalled);
    EXPECT_EQ(deletedVal, 42);
    EXPECT_EQ(target.get(), 99);
    EXPECT_EQ(source.get(), 0);
}

TEST_F(Given_CckyHandle, When_CopyConstructedOnCopyableHandle_CallsCopier)
{
    bool copierCalled = false;
    int copiedVal = -1;
    s_copier = [&](int h)
    {
        copierCalled = true;
        copiedVal = h;
        return h + 1000;
    };
    CopyableTestHandle source(42);

    CopyableTestHandle target(source);

    EXPECT_TRUE(copierCalled);
    EXPECT_EQ(copiedVal, 42);
    EXPECT_EQ(target.get(), 1042);
    EXPECT_EQ(source.get(), 42);
}

TEST_F(Given_CckyHandle, When_CopyAssignedOnCopyableHandle_ReleasesExistingAndCallsCopier)
{
    bool deleterCalled = false;
    int deletedVal = -1;
    s_deleter = [&](int h)
    {
        deleterCalled = true;
        deletedVal = h;
    };
    bool copierCalled = false;
    s_copier = [&](int h)
    {
        copierCalled = true;
        return h + 1000;
    };
    CopyableTestHandle source(99);
    CopyableTestHandle target(42);

    target = source;

    EXPECT_TRUE(deleterCalled);
    EXPECT_EQ(deletedVal, 42);
    EXPECT_TRUE(copierCalled);
    EXPECT_EQ(target.get(), 1099);
    EXPECT_EQ(source.get(), 99);
}

TEST_F(Given_CckyHandle, When_ReleaseCalled_ReturnsHandleAndZerosInternalWithoutDeleting)
{
    bool deleterCalled = false;
    s_deleter = [&](int) { deleterCalled = true; };
    TestHandle handle(42);

    int releasedVal = handle.release();

    EXPECT_EQ(releasedVal, 42);
    EXPECT_FALSE(handle.isValid());
    EXPECT_EQ(handle.get(), 0);
    EXPECT_FALSE(deleterCalled);
}

TEST_F(Given_CckyHandle, When_ResetCalledWithNewHandle_DeletesOldAndStoresNew)
{
    bool deleterCalled = false;
    int deletedVal = -1;
    s_deleter = [&](int h)
    {
        deleterCalled = true;
        deletedVal = h;
    };
    TestHandle handle(42);

    handle.reset(100);

    EXPECT_TRUE(deleterCalled);
    EXPECT_EQ(deletedVal, 42);
    EXPECT_EQ(handle.get(), 100);
}

TEST_F(Given_CckyHandle, When_InitCalledOnInvalidHandle_ReturnsReferenceToInternalHandle)
{
    TestHandle handle;

    int& ref = handle.init();
    ref = 55;

    EXPECT_TRUE(handle.isValid());
    EXPECT_EQ(handle.get(), 55);
}

TEST_F(Given_CckyHandle, When_InitCalledOnValidHandle_ThrowsCckyException)
{
    TestHandle handle(42);

    EXPECT_THROW(handle.init(), ccky::crypto::CckyException);
}

TEST_F(Given_CckyHandle, When_ComparedWithNullptr_ReturnsTrueIfInvalid)
{
    TestHandle validHandle(42);
    TestHandle invalidHandle(0);

    bool validIsNull = (validHandle == nullptr);
    bool invalidIsNull = (invalidHandle == nullptr);
    bool validIsNotNull = (validHandle != nullptr);

    EXPECT_FALSE(validIsNull);
    EXPECT_TRUE(invalidIsNull);
    EXPECT_TRUE(validIsNotNull);
}

TEST_F(Given_CckyHandle, When_ComparedWithOtherHandle_ComparesUnderlyingValues)
{
    TestHandle h1(42);
    TestHandle h2(42);
    TestHandle h3(99);

    bool isEqual = (h1 == h2);
    bool isNotEqual = (h1 != h3);

    EXPECT_TRUE(isEqual);
    EXPECT_TRUE(isNotEqual);
}

TEST_F(Given_CckyHandle, When_ConstructedWithCustomInvalidValue_IsInvalidAndDoesNotCallDeleter)
{
    bool deleterCalled = false;
    bool handleWasValid = true;
    s_deleter = [&](int) { deleterCalled = true; };
    s_isInvalid = [](int h) { return h == -1; };

    {
        TestHandle handle(-1);
        handleWasValid = handle.isValid();
    }

    EXPECT_FALSE(handleWasValid);
    EXPECT_FALSE(deleterCalled);
}

TEST_F(Given_CckyHandle, When_CustomInvalidValueSetAndZeroPassed_IsConsideredValidAndCallsDeleter)
{
    bool deleterCalled = false;
    bool handleWasValid = false;
    int deletedVal = -999;
    s_deleter = [&](int h)
    {
        deleterCalled = true;
        deletedVal = h;
    };
    s_isInvalid = [](int h) { return h == -1; };

    {
        TestHandle handle(0);
        handleWasValid = handle.isValid();
    }

    EXPECT_TRUE(handleWasValid);
    EXPECT_TRUE(deleterCalled);
    EXPECT_EQ(deletedVal, 0);
}

TEST_F(Given_CckyHandle, When_DeleterArgsTupleProvided_UnpacksTupleToDeleter)
{
    bool deleterCalled = false;
    int deletedHandle = 0;
    int receivedArg1 = 0;
    bool receivedArg2 = false;
    s_tupleDeleter = [&](int h, int a, bool b)
    {
        deleterCalled = true;
        deletedHandle = h;
        receivedArg1 = a;
        receivedArg2 = b;
    };

    {
        TupleTestHandle handle(42);
    }

    EXPECT_TRUE(deleterCalled);
    EXPECT_EQ(deletedHandle, 42);
    EXPECT_EQ(receivedArg1, 100);
    EXPECT_TRUE(receivedArg2);
}

TEST_F(Given_CckyHandle, When_PointerHandleAccessed_ArrowAndStarOperatorsWork)
{
    DummyPointed dummy{77};
    PointerTestHandle handle(&dummy);

    int arrowVal = handle->val;
    int starVal = (*handle).val;

    EXPECT_EQ(arrowVal, 77);
    EXPECT_EQ(starVal, 77);
}
